require('dotenv').config();
const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const net = require('net');
const disposableDomains = require('disposable-email-domains');
const freeDomains = require('free-email-domains');
const path = require('path');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const app = express();

// Security and Logging
app.use(helmet({
  contentSecurityPolicy: false // Disabled for the demo's inline scripts and Tailwind CDN
}));
app.use(morgan('dev'));
app.use(cors());
app.use(express.json());

// Rate Limiting (100 requests per 15 mins)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes' }
});

// RapidAPI Protection Middleware
const rapidApiMiddleware = (req, res, next) => {
  const RAPIDAPI_SECRET = process.env.RAPIDAPI_PROXY_SECRET;
  if (!RAPIDAPI_SECRET) return next();
  const incomingSecret = req.headers['x-rapidapi-proxy-secret'];
  if (incomingSecret === RAPIDAPI_SECRET) return next();
  console.warn(`Blocked direct access attempt from IP: ${req.ip}`);
  return res.status(403).json({
    error: 'Forbidden',
    message: 'Access Denied. Please subscribe and access this API via RapidAPI.'
  });
};

app.use('/api/', apiLimiter, rapidApiMiddleware);

// Demo Rate Limiting (much stricter — 10 requests per 15 mins)
const demoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demo limit reached. Subscribe on RapidAPI for unlimited access.' }
});
app.use('/demo/', demoLimiter);

// Serve Static Frontend Landing Page
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────
// HELPER: SMTP Mailbox Verification
// Connects to the domain's mail server and checks if the mailbox exists
// ─────────────────────────────────────────────────────────────
function verifyMailbox(email, mxHost) {
  return new Promise((resolve) => {
    const timeout = 4000; // 4 second timeout
    const socket = new net.Socket();
    let step = 0;
    let result = { exists: null, smtpResponse: '' }; // null = inconclusive

    socket.setTimeout(timeout);

    socket.on('data', (data) => {
      const response = data.toString();

      if (step === 0) {
        // Server greeting
        if (response.startsWith('220')) {
          socket.write('HELO emailguard.com\r\n');
          step++;
        } else {
          result.smtpResponse = response.trim();
          socket.destroy();
        }
      } else if (step === 1) {
        // HELO response
        if (response.startsWith('250')) {
          socket.write('MAIL FROM:<verify@emailguard.com>\r\n');
          step++;
        } else {
          socket.destroy();
        }
      } else if (step === 2) {
        // MAIL FROM response
        if (response.startsWith('250')) {
          socket.write(`RCPT TO:<${email}>\r\n`);
          step++;
        } else {
          socket.destroy();
        }
      } else if (step === 3) {
        // RCPT TO response — THIS is the key check
        result.smtpResponse = response.trim();
        if (response.startsWith('250')) {
          result.exists = true;  // Mailbox confirmed to exist
        } else if (response.startsWith('550') || response.startsWith('551') || response.startsWith('552') || response.startsWith('553')) {
          result.exists = false; // Mailbox does NOT exist
        }
        // else: inconclusive (some servers don't reveal this info)
        socket.write('QUIT\r\n');
        step++;
      } else {
        socket.destroy();
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', () => {
      socket.destroy();
    });

    socket.on('close', () => {
      resolve(result);
    });

    socket.connect(25, mxHost);
  });
}

// ─────────────────────────────────────────────────────────────
// HELPER: Username Pattern Analysis
// Detects suspicious / gibberish usernames
// ─────────────────────────────────────────────────────────────
function analyzeUsername(localPart) {
  const flags = [];
  let suspicionScore = 0;

  // 1. Too short (a@, ab@)
  if (localPart.length <= 2) {
    flags.push('too_short');
    suspicionScore += 10;
  }

  // 2. Too long (more than 30 chars is unusual)
  if (localPart.length > 30) {
    flags.push('unusually_long');
    suspicionScore += 15;
  }

  // 3. Excessive numbers — "user928374651"
  const digitCount = (localPart.match(/\d/g) || []).length;
  const digitRatio = digitCount / localPart.length;
  if (digitRatio > 0.5 && localPart.length > 4) {
    flags.push('excessive_numbers');
    suspicionScore += 20;
  }

  // 4. No vowels (likely gibberish) — "xkjmwqr"
  const vowelCount = (localPart.match(/[aeiou]/gi) || []).length;
  if (vowelCount === 0 && localPart.length > 3) {
    flags.push('no_vowels_gibberish');
    suspicionScore += 25;
  }

  // 5. Consonant clusters — 4+ consonants in a row like "brtsnk"
  if (/[^aeiou0-9._-]{5,}/i.test(localPart)) {
    flags.push('consonant_cluster');
    suspicionScore += 15;
  }

  // 6. Random-looking pattern: alternating chars with digits like "a1b2c3d4"
  if (/^([a-z]\d){3,}$/i.test(localPart) || /^(\d[a-z]){3,}$/i.test(localPart)) {
    flags.push('alternating_pattern');
    suspicionScore += 20;
  }

  // 7. All same character repeated — "aaaaaaa"
  if (/^(.)\1{3,}$/.test(localPart)) {
    flags.push('repeated_chars');
    suspicionScore += 25;
  }

  // 8. Contains "test", "fake", "temp", "spam", "trash"
  if (/\b(test|fake|temp|spam|trash|dummy|sample|noreply)\b/i.test(localPart)) {
    flags.push('suspicious_keyword');
    suspicionScore += 20;
  }

  return {
    flags,
    suspicionScore: Math.min(suspicionScore, 50), // cap at 50
    isLikelyGibberish: flags.includes('no_vowels_gibberish') || flags.includes('consonant_cluster')
  };
}

// Common role-based prefixes
const roleBasedPrefixes = [
  'admin', 'info', 'support', 'sales', 'billing', 'contact', 'hello',
  'marketing', 'hr', 'careers', 'help', 'team', 'office', 'webmaster',
  'postmaster', 'abuse', 'hostmaster', 'security', 'noreply', 'no-reply'
];

// ─────────────────────────────────────────────────────────────
// SHARED VALIDATION HANDLER
// ─────────────────────────────────────────────────────────────
const validateHandler = async (req, res) => {
  const startTime = Date.now();
  const { email } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Email field is required in the JSON body.' });
  }

  // Basic Format Check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.json({
      email,
      isValidFormat: false,
      score: 100,
      riskLevel: "Critical",
      action: "Block",
      reason: "Invalid email format.",
      processingTimeMs: Date.now() - startTime
    });
  }

  const [localPart, domain] = email.toLowerCase().split('@');
  let score = 0;
  const riskFactors = []; // Human-readable reasons for the score

  // ── 1. Disposable Email Check ───────────────────────────
  const isDisposable = disposableDomains.includes(domain);
  if (isDisposable) {
    score += 80;
    riskFactors.push('Disposable/temporary email domain detected');
  }

  // ── 2. Free/Personal vs Business Check ──────────────────
  const isFree = freeDomains.includes(domain);
  if (isFree && !isDisposable) {
    score += 10;
    riskFactors.push('Free/personal email provider (not business)');
  }

  // ── 3. Role-based Address Check ─────────────────────────
  const isRoleBased = roleBasedPrefixes.includes(localPart);
  if (isRoleBased) {
    score += 25;
    riskFactors.push(`Role-based address "${localPart}@" — likely not a real person`);
  }

  // ── 4. DNS Checks (MX, SPF, DKIM) ──────────────────────
  let hasMxRecords = false;
  let mxRecords = [];
  let hasSpfRecord = false;
  let hasDkimRecord = false;

  try {
    mxRecords = await dns.resolveMx(domain);
    if (mxRecords && mxRecords.length > 0) {
      hasMxRecords = true;
      mxRecords.sort((a, b) => a.priority - b.priority);
    }
  } catch (err) {
    hasMxRecords = false;
  }

  if (!hasMxRecords) {
    score += 50;
    riskFactors.push('Domain has no MX records — cannot receive email');
  }

  try {
    const txtRecords = await dns.resolveTxt(domain);
    hasSpfRecord = txtRecords.some(recordArray =>
      recordArray.some(record => record.toLowerCase().startsWith('v=spf1'))
    );
  } catch (err) {
    hasSpfRecord = false;
  }

  if (!hasSpfRecord) {
    score += 10;
    riskFactors.push('No SPF record — domain email security is weak');
  }

  // DKIM check (common selectors)
  const dkimSelectors = ['google', 'default', 'selector1', 'selector2', 'k1'];
  for (const selector of dkimSelectors) {
    try {
      const dkimRecords = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      if (dkimRecords.some(r => r.join('').includes('v=DKIM1'))) {
        hasDkimRecord = true;
        break;
      }
    } catch (err) {
      // selector not found, try next
    }
  }

  // ── 5. Username Pattern Analysis ────────────────────────
  const usernameAnalysis = analyzeUsername(localPart);
  if (usernameAnalysis.suspicionScore > 0) {
    score += usernameAnalysis.suspicionScore;
    if (usernameAnalysis.isLikelyGibberish) {
      riskFactors.push('Username appears to be gibberish/randomly generated');
    }
    if (usernameAnalysis.flags.includes('excessive_numbers')) {
      riskFactors.push('Username contains excessive numbers');
    }
    if (usernameAnalysis.flags.includes('suspicious_keyword')) {
      riskFactors.push('Username contains suspicious keyword (test/fake/temp)');
    }
    if (usernameAnalysis.flags.includes('too_short')) {
      riskFactors.push('Username is suspiciously short');
    }
  }

  // ── 6. SMTP Mailbox Verification ────────────────────────
  let mailboxExists = null; // null = could not determine
  let smtpResponse = '';

  if (hasMxRecords) {
    try {
      const bestMx = mxRecords[0].exchange;
      const smtpResult = await verifyMailbox(email.toLowerCase(), bestMx);
      mailboxExists = smtpResult.exists;
      smtpResponse = smtpResult.smtpResponse;

      if (smtpResult.exists === false) {
        score += 40;
        riskFactors.push('SMTP verification failed — mailbox does not exist on server');
      }
    } catch (err) {
      // SMTP check failed, leave as inconclusive
    }
  }

  // ── Cap & Classify ──────────────────────────────────────
  score = Math.min(score, 100);

  let riskLevel, action;
  if (score >= 70) {
    riskLevel = 'Critical';
    action = 'Block';
  } else if (score >= 40) {
    riskLevel = 'Medium';
    action = 'Review';
  } else {
    riskLevel = 'Low';
    action = 'Allow';
  }

  const processingTimeMs = Date.now() - startTime;

  res.json({
    email,
    isValidFormat: true,
    score,
    riskLevel,
    action,
    riskFactors,
    domainType: isDisposable ? 'Disposable' : (isFree ? 'Personal' : 'Business'),
    intelligence: {
      isDisposable,
      isFreeProvider: isFree,
      isRoleBased,
      mailboxVerification: {
        exists: mailboxExists,
        smtpResponse: smtpResponse || null
      },
      usernameAnalysis: {
        flags: usernameAnalysis.flags,
        suspicionScore: usernameAnalysis.suspicionScore,
        isLikelyGibberish: usernameAnalysis.isLikelyGibberish
      },
      dns: {
        hasMxRecords,
        hasSpfRecord,
        hasDkimRecord,
        mxHost: hasMxRecords ? mxRecords[0].exchange : null
      }
    },
    processingTimeMs
  });
};

// Protected endpoint (RapidAPI customers)
app.post('/api/validate', validateHandler);

// Public demo endpoint (landing page — strict rate limit, no auth)
app.post('/demo/validate', validateHandler);

// Root route is automatically handled by express.static serving public/index.html

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`EmailGuard API is running on http://localhost:${PORT}`);
});
