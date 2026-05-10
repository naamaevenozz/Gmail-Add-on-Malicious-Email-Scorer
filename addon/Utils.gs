/**
 * Utils.gs - Email data extraction
 *

/**
 * Build the full EmailPayload that the backend expects.
 * @param {string} messageId
 * @returns {Object}
 */
function extractEmailData(messageId) {
  const message      = GmailApp.getMessageById(messageId);
  const rawHeaders   = getRawHeaders(message);
  const senderDomain = extractDomain(message.getFrom());

  return {
    message_id:   messageId,
    sender:       extractSender(message),
    auth:         parseAuthResults(rawHeaders),
    subject:      message.getSubject(),
    urls:         extractUrls(message.getBody()),
    attachments:  extractAttachmentMeta(message.getAttachments()),
    body_signals: extractBodySignals(message.getPlainBody(), message.getBody(), senderDomain),
    metadata: {
      timestamp:      message.getDate().toISOString(),
      received_count: countReceivedHeaders(rawHeaders),
      sender_ip:      extractSenderIp(rawHeaders),
    },
  };
}

// Sender
function extractSender(message) {
  const fromRaw = message.getFrom();
  return {
    from_raw:     fromRaw,
    from_domain:  extractDomain(fromRaw),
    display_name: extractDisplayName(fromRaw),
  };
}

/** "PayPal Support <support@paypa1.com>" → "paypa1.com" */
function extractDomain(fromRaw) {
  const match = fromRaw.match(/@([\w.-]+)/);
  return match ? match[1].toLowerCase() : fromRaw.toLowerCase();
}

/** "PayPal Support <support@paypa1.com>" → "PayPal Support" */
function extractDisplayName(fromRaw) {
  const match = fromRaw.match(/^"?([^"<]+?)"?\s*</);
  if (match) return match[1].trim();
  const local = fromRaw.match(/^([^@<]+)/);
  return local ? local[1].trim() : fromRaw;
}

// Auth headers (SPF / DKIM / DMARC / Reply-To)

function getRawHeaders(message) {
  return {
    'Authentication-Results': message.getHeader('Authentication-Results') || '',
    'Reply-To':               message.getHeader('Reply-To')               || '',
    'Return-Path':            message.getHeader('Return-Path')            || '',
    'Received':               message.getHeader('Received')               || '',
  };
}

function parseAuthResults(rawHeaders) {
  const auth = rawHeaders['Authentication-Results'] || '';

  const spfMatch   = auth.match(/spf=(pass|fail|softfail|neutral|none)/i);
  const dkimMatch  = auth.match(/dkim=(pass|fail|none)/i);
  const dmarcMatch = auth.match(/dmarc=(pass|fail|none)/i);

  const replyTo    = rawHeaders['Reply-To']    || null;
  const returnPath = rawHeaders['Return-Path'] || null;

  return {
    spf:         spfMatch   ? spfMatch[1].toLowerCase()   : 'none',
    dkim:        dkimMatch  ? dkimMatch[1].toLowerCase()  : 'none',
    dmarc:       dmarcMatch ? dmarcMatch[1].toLowerCase() : 'none',
    reply_to:    replyTo    ? replyTo.trim()    : null,
    return_path: returnPath ? returnPath.trim() : null,
  };
}

function countReceivedHeaders(rawHeaders) {
  return rawHeaders['Received'] ? 1 : 0;
}

/**
 * Extract the originating IP address from the first Received header.
 * Received headers look like: "from mail.example.com ([203.0.113.1]) by ..."
 * We extract the first IPv4 address in square brackets.
 */
function extractSenderIp(rawHeaders) {
  const received = rawHeaders['Received'] || '';
  const match = received.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  return match ? match[1] : null;
}

// URLs

/**
 * Extract up to 20 unique (href, display_text) pairs from the HTML body.
 * Strips mailto: links and deduplicates by href.
 */
function extractUrls(html) {
  const urls  = [];
  const seen  = {};
  const re    = /<a[^>]+href=["']([^"'#][^"']*?)["'][^>]*>([\s\S]*?)<\/a>/gi;

  let match;
  while ((match = re.exec(html)) !== null) {
    const href        = match[1].trim();
    const rawText     = match[2].replace(/<[^>]+>/g, '').trim();
    const displayText = rawText.substring(0, 120);

    if (!href || href.startsWith('mailto:') || seen[href]) continue;
    seen[href] = true;
    urls.push({ display_text: displayText || href, href: href });
    if (urls.length >= 20) break;
  }
  return urls;
}

// Attachments

function extractAttachmentMeta(attachments) {
  return attachments.map(function(att) {
    return {
      filename:   att.getName(),
      mime_type:  att.getContentType(),
      size_bytes: att.getSize(),
    };
  });
}

// Body signals - phrase extraction + structural signals

/**
 * Scan plain text (and HTML for pixel detection) for pre-defined signals.
 * The raw body never leaves the add-on client - only matched metadata is sent.
 *
 * @param {string} text  Plain-text body
 * @param {string} html  HTML body (used only for tracking-pixel detection)
 * @param {string} senderDomain  Sender's domain (used to filter first-party pixels)
 */
function extractBodySignals(text, html, senderDomain) {
  const URGENCY = [
    /verify immediately/i, /act now/i, /account.{0,10}limited/i,
    /urgent.{0,10}action/i, /within 24 hours/i, /immediately/i,
    /account.{0,10}suspend/i, /will be (closed|deactivated|terminated)/i,
    /limited time/i, /expires? (today|soon|in \d+ hour)/i,
  ];

  const CRED = [
    /enter.{0,10}password/i, /confirm.{0,10}pin/i,
    /update.{0,10}credentials/i, /sign in to verify/i,
    /verify your identity/i, /reset your password/i,
    /confirm your (email|account|identity)/i,
  ];

  const FINANCIAL = [
    /wire transfer/i, /payment.{0,10}failed/i,
    /invoice.{0,10}attached/i, /bank account/i,
    /refund.{0,10}pending/i, /unauthorized (charge|transaction)/i,
    /billing information/i, /credit card.{0,10}(expire|update)/i,
  ];

  // OTP relay - asking user to forward a code they received from another service
  const OTP = [
    /enter the (code|otp|pin|verification code) (you received|we? sent|that was sent)/i,
    /do not share (your )?(otp|code|pin|verification code) with/i,
    /one[- ]?time (password|code|pin) (you received|sent to you)/i,
    /enter (your )?[46][ -]?digit (code|pin|otp)/i,
    /relay (the )?(code|otp|verification)/i,
    /forward (the )?(code|otp|verification code)/i,
    /provide (the )?(authentication|verification) code/i,
  ];

  // Fake security alert - mimics legitimate login/activity notifications
  const FAKE_SECURITY = [
    /if this was you.{0,20}(ignore|no action|disregard)/i,
    /if you did not (do|make|request|initiate) this/i,
    /unusual (login|sign[- ]?in|activity|access) detected/i,
    /we noticed (unusual|suspicious|an? (unauthorized|unrecognized))/i,
    /unauthorized (access|login|sign[- ]?in|device)/i,
    /unrecognized (device|login|sign[- ]?in|location)/i,
    /suspicious (activity|login|sign[- ]?in) (was )?detected/i,
    /your account (has been |was )?(accessed|compromised) from/i,
  ];

  // Generic impersonal greeting - a bulk-phishing indicator
  const GENERIC_GREETING = [
    /^dear (customer|user|member|valued (customer|member)|account holder|sir|madam|friend|client)\b/im,
    /^hello (customer|user|member|there)\b/im,
    /^greetings (customer|user|member)\b/im,
    /^dear (valued )?account holder\b/im,
  ];

  // Specific misspellings common in phishing - low-confidence signal
  const MISSPELLINGS = [
    /\brecieve\b/i, /\binfomation\b/i, /\baccout\b/i, /\bverfy\b/i,
    /\bpasswrod\b/i, /\bconfrm\b/i, /\bimmidately\b/i,
    /\bauthentification\b/i, /\bnotifcation\b/i, /\bverfication\b/i,
    /\bcompromized\b/i, /\btemporarilly\b/i, /\baccound\b/i,
    /\bvalidattion\b/i, /\bsusspicious\b/i, /\bactiviti\b/i,
    /\bunusall\b/i, /\bverfiy\b/i,
  ];

  return {
    char_count:              text.length,
    urgency_phrases:         matchPhrases(text, URGENCY),
    credential_phrases:      matchPhrases(text, CRED),
    financial_phrases:       matchPhrases(text, FINANCIAL),
    otp_phrases:             matchPhrases(text, OTP),
    has_invisible_text:      detectInvisibleText(text),
    generic_greeting:        GENERIC_GREETING.some(function(re) { return re.test(text); }),
    fake_security_alert:     FAKE_SECURITY.some(function(re) { return re.test(text); }),
    tracking_pixel_domains:  extractTrackingPixels(html || '', senderDomain || ''),
    spelling_error_count:    MISSPELLINGS.filter(function(re) { return re.test(text); }).length,
  };
}

/** Returns matched strings (not positions) for each pattern that fires. */
function matchPhrases(text, patterns) {
  var found = [];
  for (var i = 0; i < patterns.length; i++) {
    var m = text.match(patterns[i]);
    if (m) found.push(m[0].substring(0, 60));
  }
  return found;
}

/**
 * Detect zero-width / invisible Unicode characters used to bypass keyword
 * filters or confuse text parsers.
 */
function detectInvisibleText(text) {
  return /[​‌‍­‮‭]/.test(text);
}

/**
 * Scan the HTML body for 1×1 tracking pixels.
 * Returns the list of external domains hosting such pixels - pixels served
 * from the sender's own domain are filtered out (likely analytics, not hostile).
 *
 * A tracking pixel is a remote image with width ≤ 1 and height ≤ 1.
 * When the mail client loads it, it confirms the email was opened and reveals
 * the recipient's IP address and client fingerprint to the pixel host.
 */
function extractTrackingPixels(html, senderDomain) {
  if (!html) return [];
  var pixels = [];
  var seen   = {};
  var re     = /<img\b([^>]*)>/gi;
  var match;

  while ((match = re.exec(html)) !== null) {
    var attrs = match[1];

    // Attribute-based dimension check: width="1" height="1" (or 0)
    var wMatch = attrs.match(/width=["']?(\d+)["']?/i);
    var hMatch = attrs.match(/height=["']?(\d+)["']?/i);
    var isPixel = wMatch && hMatch &&
                  parseInt(wMatch[1], 10) <= 1 &&
                  parseInt(hMatch[1], 10) <= 1;

    // Style-based dimension check: style="width:1px; height:1px"
    if (!isPixel) {
      var styleMatch = attrs.match(/style=["']([^"']*)["']/i);
      if (styleMatch) {
        var s = styleMatch[1];
        isPixel = /width\s*:\s*[01]px/i.test(s) && /height\s*:\s*[01]px/i.test(s);
      }
    }
    if (!isPixel) continue;

    var srcMatch = attrs.match(/src=["']([^"']+)["']/i);
    if (!srcMatch) continue;

    var domainMatch = srcMatch[1].match(/https?:\/\/([^\/\?#]+)/i);
    if (!domainMatch) continue;

    var pixelDomain = domainMatch[1].toLowerCase();
    if (pixelDomain === senderDomain || seen[pixelDomain]) continue;
    seen[pixelDomain] = true;
    pixels.push(pixelDomain);
  }
  return pixels;
}