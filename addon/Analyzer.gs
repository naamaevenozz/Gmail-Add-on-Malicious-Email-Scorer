/**
 * Analyzer.gs - Backend communication
 *
 * Read the backend URL from Script Properties.
 * Set it via: Apps Script Editor → Project Settings → Script Properties
 *   Key: BACKEND_URL   Value: https://your-app.onrender.com
 */
function getBackendUrl() {
  var url = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  if (!url) {
    throw new Error('BACKEND_URL script property is not set. ' +
                    'Go to Project Settings → Script Properties and add it.');
  }
  return url.replace(/\/$/, '');
}

/**
 * POST the extracted email metadata to the backend /analyze endpoint.
 *
 * @param {Object} emailData  - the payload built by Utils.gs::extractEmailData()
 * @returns {Object}          - parsed VerdictResponse, or { error: true, code, message }
 */
function analyzeEmail(emailData) {
  var backendUrl;
  try {
    backendUrl = getBackendUrl();
  } catch (e) {
    return { error: true, code: 0, message: e.message };
  }
  Logger.log("Sending request to: " + backendUrl + "/analyze");

  var options = {
    'method': 'post',
    'contentType': 'application/json',
    'headers': {
      'ngrok-skip-browser-warning': 'true'
    },
    'payload': JSON.stringify(emailData),
    'muteHttpExceptions': true
  };

  var response;
  try {
    response = UrlFetchApp.fetch(backendUrl + '/analyze', options);
  } catch (e) {
    // Network-level failure (DNS, timeout, SSL)
    Logger.log('Network error calling backend: ' + e.message);
    return { error: true, code: 0, message: 'Network error - backend unreachable.' };
  }

  var code = response.getResponseCode();
  var body = response.getContentText();

  if (code === 200) {
    try {
      return JSON.parse(body);
    } catch (e) {
      Logger.log('Failed to parse backend response: ' + body.substring(0, 200));
      return { error: true, code: 200, message: 'Backend returned invalid JSON.' };
    }
  }

  // 429 - rate limited
  if (code === 429) {
    return { error: true, code: 429, message: 'Too many requests. Please wait a moment.' };
  }

  // 422 - our payload failed validation (should not happen in production)
  if (code === 422) {
    Logger.log('Payload validation error: ' + body.substring(0, 500));
    return { error: true, code: 422, message: 'Payload validation error.' };
  }

  // 5xx or anything else - do not surface details to the card
  Logger.log('Backend error ' + code + ': ' + body.substring(0, 200));
  return { error: true, code: code, message: 'Analysis service error. Please try again.' };
}