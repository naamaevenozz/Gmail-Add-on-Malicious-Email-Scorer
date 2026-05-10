# Email Scorer - Phishing & Threat Detection for Gmail

A Gmail add-on backed by a FastAPI service that scores every email you open for phishing, impersonation, and social engineering - and explains the verdict in plain language.


<img width="454" height="864" alt="image" src="https://github.com/user-attachments/assets/4f86d818-40a2-44d3-bfd2-950ac823800f" />

---

## Getting Started

### Prerequisites

- Python 3.11+
- A Google account with Gmail
- An OpenAI API key (required for LLM explanations)
- Optional: Google Safe Browsing, VirusTotal, and WHOIS XML API keys for richer threat intelligence


### Set environment variables

Copy the template and fill in your keys:

```bash
cp backend/.env.example backend/.env
```

#### How to get an OpenAI API key

https://developers.openai.com/api/docs/quickstart

### 1. Run the backend

```bash
# Make sure you are in the root directory of the project, then run:
python -m uvicorn main:app --reload --app-dir backend
```

### 2. Expose locally for Gmail (development)

Gmail add-ons require HTTPS. Use [ngrok](https://ngrok.com) to create a tunnel:

```bash
ngrok http 8000
```

Copy the `https://...ngrok-free.app` URL - you will need it in the add-on manifest.

### 3. Deploy the Gmail add-on

1. Open [Google Apps Script](https://script.google.com) and create a new project.
2. Paste the contents of `addon/Code.gs` and set `BACKEND_URL` to your ngrok URL.
3. Go to **Deploy → Test deployments** and install the add-on in your Gmail.
4. Open any email in Gmail - the add-on panel appears on the right.


## Architecture

```
Gmail Add-on (Google Apps Script)
        |  HTTPS POST /analyze
        v
+-------------------------------------------------+
|                  FastAPI Backend                |
|                                                 |
|  Layer 1 - Normalizer                           |
|    Strip invisible Unicode, sanitise HTML,      |
|    detect prompt-injection in all text fields.  |
|    Gate: if injection detected, skip Layer 4.   |
|                                                 |
|  Layer 2 - Deterministic Signals                |
|    ~30 pure functions on sanitised metadata.    |
|    Auth (SPF/DKIM/DMARC), sender domain,        |
|    URL analysis, body language, attachments.    |
|                                                 |
|  Layer 3 - Threat Intelligence                  |
|    Parallel: Safe Browsing, VirusTotal,         |
|    WHOIS domain age, IP geolocation.            |
|    Each call: 5 s timeout, graceful on no key.  |
|                                                 |
|  Layer 5 - Weighted Aggregator                  |
|    score = clamp(sum(weights) - trust_discount, |
|            0, 100)                              |
|    Verdict thresholds: >=60 MALICIOUS,          |
|    >=30 SUSPICIOUS, <30 SAFE.                   |
|                                                 |
|  Layer 4 - LLM Reasoning (last, intentionally) |
|    Plain-language explanation of the verdict.   |
|    The LLM explains -- it does not decide.      |
|    Skipped when injection detected or <2        |
|    signals fired.                               |
+-------------------------------------------------+
```

> **Why is Layer 4 numbered out of order?**
> The LLM runs *last*, after the verdict is already determined. The number reflects the conceptual layer in the security model (enrichment), not execution order. The scoring pipeline is entirely deterministic - the LLM cannot change the verdict.

### Architecture & Engineering Decisions:

## LLM Strategy

### The LLM explains - it does not decide

The verdict and score are fully determined before the LLM is called. The LLM's only job is to translate the fired signal IDs into plain language that a non-technical person can act on. This separation ensures:

- **Predictability**: the same signals always produce the same verdict, regardless of what the LLM says.
- **Auditability**: you can explain any verdict without referencing the LLM output.
- **Failure resilience**: if the LLM call times out or errors, the verdict and score are still returned.

### Judgment-aware prompting

The system prompt is verdict-aware. For SAFE emails, the LLM is explicitly forbidden from using words like "suspicious", "attacker", or "phishing" - because the verdict is safe, and alarming language would contradict it. For SUSPICIOUS/MALICIOUS emails, the LLM is restricted to describing only the signals that actually fired.

This is a deliberate application of the insight from Perez et al. (2022) on prompt injection: prompts that specify what the model *must not do* are more robust than prompts that only specify what it should do.

### SALT boundary (prompt-injection defence)

Every LLM call wraps email-derived data in a per-request random boundary token generated with `secrets.token_hex(8)`. The system prompt names the boundary explicitly and instructs the model to treat everything between the markers as untrusted attacker-supplied data - never as instructions.

```
###_BOUNDARY_a3f9c1d2e8b4_###
{ "subject_keywords": ["verify", "account", "immediately"], ... }
###_BOUNDARY_a3f9c1d2e8b4_###
```

An injected instruction like `"Ignore all previous instructions"` lands inside the boundary, where it is named as attacker content by the system prompt. The token is regenerated on every request so an attacker cannot craft a payload that pre-escapes the boundary.

### LLM-as-Judge

After the primary analyst returns its explanation, a second independent LLM call (the Judge) validates it against three criteria:

1. **Verdict consistency** - does the tone match the verdict? A SAFE explanation must not use alarming language.
2. **Grounding** - does the explanation only describe risks that correspond to fired signals?
3. **Safety** - does the explanation contain leaked personal data, raw URLs, or injected content?

If the Judge finds issues, it returns a corrected version. If the Judge call fails for any reason, the original explanation is returned unchanged. The judge is a backstop, not a dependency.
### Outbound email protection

To maximize cost-efficiency and avoid wasting API credits, I blocked outbound email analysis because there is no security value in paying to scan content the user wrote themselves.

## Scoring Engine

### Why not machine learning?

I considered training a classifier on a labeled phishing dataset. I rejected it for one specific reason: No current, publicly available phishing dataset preserves email headers.

Headers carry SPF, DKIM, and DMARC validation results - the reliable sign that an email is legitimate. Every major public dataset (CEAS 2008, SpamAssassin, TREC 2007) strips headers before publishing for privacy reasons. A model trained on headerless data only learns body text patterns, making it blind to the layer of validation that true email security depends on.

Expert-weighted signals allow us to encode what experts know from published research directly into the weights, without the need for a dataset.

### How weights are set
Each signal weight represents the marginal increase in phishing probability that the signal contributes, calibrated against published threat research (see [Research](#Research-and-Inspiration)). The parameters are not perfectly calibrated, it is a score that ranks emails correctly relative to each other, so that the audit thresholds hold across a variety of email types.

Signals are divided into three groups with different calibration methods:

- **Text signals** (urgency, authorization requests, general greetings, etc.) - Statistically calibrated using a dataset of tagged email message bodies.

- **URL signals** (shorteners, IP-based URLs, complexity patterns, etc.) - Statistically calibrated using a dataset of tagged URL features.

- **Everything else** (authentication results, sender domain checks, attachments, threat intelligence) - No public dataset was found that includes these as tagged features, so the weights come solely from expert judgment and published research.

### Signal catalog

| ID | Category | Weight | Description |
|----|----------|--------|-------------|
| `DKIM_FAIL` | Auth | +25 | DKIM signature absent or invalid |
| `SPF_FAIL` | Auth | +20 | SPF check failed |
| `DMARC_FAIL` | Auth | +18 | DMARC policy failed |
| `DKIM_PASS` | Auth | -15 | DKIM signature verified |
| `SPF_PASS` | Auth | -10 | SPF check passed |
| `DMARC_PASS` | Auth | -8 | DMARC policy passed |
| `PUNYCODE_DOMAIN` | Sender | +100 | Punycode in sender domain (critical blow) |
| `HOMOGLYPH_DOMAIN` | Sender | +35 | Sender domain is visually similar to a known brand |
| `BRAND_IMPERSONATION` | Sender | +30 | Subject/body claims a known brand; sender domain does not match |
| `DOMAIN_NEW` | Sender | +20 | Sender domain registered < 90 days ago |
| `REPLY_MISMATCH` | Sender | +20 | Reply-to domain differs from From domain |
| `DOUBLE_EXT` | Attachment | +100 | Attachment uses double extension (e.g. `.pdf.exe`) (critical blow) |
| `SUSPICIOUS_ATTACHMENT` | Attachment | +35 | Executable or high-risk attachment type |
| `VIRUSTOTAL_HIT` | Threat Intel | +100 | URL flagged by VirusTotal (critical blow*) |
| `SAFE_BROWSING_HIT` | Threat Intel | +80 | URL flagged by Google Safe Browsing |
| `LINK_MISMATCH` | URL | +25 | Display text and href point to different domains |
| `URL_SHORTENER` | URL | +20 | URL uses a shortening service |
| `URL_COMPLEXITY_RISK` | URL | +15 | URL has multiple anomaly indicators |
| `INVISIBLE_TEXT` | Body | +20 | Invisible/hidden characters in email body |
| `URGENCY_HIGH` | Body | +20 | High-pressure urgency language |
| `CRED_REQUEST` | Body | +25 | Requests passwords or account credentials |
| `OTP_REQUEST` | Body | +30 | Asks user to share a one-time code |
| `FINANCIAL_MANIP` | Body | +20 | Financial manipulation language |
| `GENERIC_GREETING` | Body | +10 | No personal greeting |
| `TRACKING_PIXEL` | Body | +5 | Tracking pixel detected |
| `GEOLOCATION_RISK` | Threat Intel | +15 | Email relayed through high-risk geography |

\*`VIRUSTOTAL_HIT` is a critical blow (instant score 100) **unless** full authentication passes (all three of SPF + DKIM + DMARC) AND the VirusTotal detection count is <= 5. This exception handles the real-world pattern where a legitimate bulk sender's shared infrastructure occasionally appears on low-confidence blocklists.

### Trust discounts

When all three authentication signals pass, an additional -15 bonus is applied on top of the individual discounts (maximum combined discount: -48). A fully-authenticated email with no other signals will always score below the SUSPICIOUS threshold.

### What reaches OpenAI - privacy by design

Out of concern about sending email content to a third-party model, I made sure that raw content never reaches OpenAI in the first place.
The LLM only receives metadata, the LLM does not see the email body, the subject line, file names, IP addresses, or links.

**What the LLM never receives**: The email body, the full subject string, the sender's display name, the recipient's address, any URLs, any attachment names, or any IP addresses.

**Even when passing a URL to VirusTotal and Safe Browsing, the system removes identifying parameters.
**---

---
### More information

### The Dissonance Problem
During testing, I encountered situations where an email would be rated SAFE but the UI would display context-free justifications that could be stressful.
To do this, I implemented context-aware label rewriting for emails with a SAFE or LOW_RISK verdict, a set of letter labels are rewritten to their benign counterparts before being sent to the UI. The rewriting is only applied to the *display* layer - the LLM always accepts the original, unmodified letter labels.

### Text layer calibration
To make sure the scoring wasn't a guess, I ran a calibration script (tools/text_layer_calibration.py) on a real dataset (from Kaggle (`phishing_legit_dataset_KD_10000.csv`), containing 6,000 phishing and 4,000 legitimate emails labeled at the body-text level.
The script used logistic regression to test which signals actually predicted phishing in the field. The result was encouraging (AUC of 0.769), and the data provided us with a strong statistical anchor.

However, I noticed that critical signals such as financial fraud (FINANCIAL_MANIP) almost never appeared in this particular dataset. If I had relied only on dry statistics, the system would have received a score of 0 for these threats and become blind.

My decision: I combined the statistical analysis with expert judgment (Expert Judgment). In places where data was lacking, I relied on research and familiarity with the real world of threats to ensure that the system protects the user from all types of phishing, not just those that appeared in the table.

### URL layer calibration
To refine the link detection, I ran the script (tools/url_layer_calibration.py) on a huge dataset of about 188,000 URLs (half phishing and half legitimate).
The goal was to see if the "red lights" I had set in the backend were actually lighting up in the right places.
There were things that statistics couldn't solve. For example, LINK_MISMATCH (when the link text doesn't match the real address) requires the context of the entire email, not just the URL itself. In such cases, I preferred to rely on professional judgment Articles.

### For further development

Optimization and Caching: Adding a caching layer that will temporarily store analysis results based on the unique identifier of the email. This will prevent duplicate API calls for the same message, improve user response speed, and significantly save on infrastructure costs.

Continuous model training: Instead of relying on static weights that are pre-calibrated on a historical dataset, the next step is to train a dedicated ML model based on a dataset that is continuously updated (including feedback from end users). This will allow the system to identify new phishing trends and adjust the weights automatically and in real time.

## Research and Inspiration

### Email authentication

- Kitterman, S. (2014). *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email*. RFC 7208. https://tools.ietf.org/html/rfc7208
- Crocker, D., Hansen, T., & Kucherawy, M. (2011). *DomainKeys Identified Mail (DKIM) Signatures*. RFC 6376. https://tools.ietf.org/html/rfc6376
- Kucherawy, M., & Zwicky, E. (2015). *Domain-based Message Authentication, Reporting, and Conformance (DMARC)*. RFC 7489. https://tools.ietf.org/html/rfc7489

### Phishing signals and detection methodology

- Ho, G., Cidon, A., Gavish, L., Schweighauser, M., Paxson, V., Savage, S., Voelker, G. M., & Tygar, J. D. (2019). Detecting and characterizing lateral phishing at scale. *USENIX Security Symposium*. https://www.usenix.org/conference/usenixsecurity19/presentation/ho
- Oest, A., Safei, Y., Doupe, A., Ahn, G. J., Wardman, B., & Warner, G. (2018). Inside a phisher's mind: Understanding the anti-phishing ecosystem through phishing kit analysis. *APWG eCrime*. https://ieeexplore.ieee.org/document/8567711
- Basit, A., Zafar, M., Liu, X., Javed, A. R., Jalil, Z., & Kifayat, K. (2021). A comprehensive survey of AI-enabled phishing attacks detection techniques. *Telecommunication Systems*. https://link.springer.com/article/10.1007/s11235-020-00733-2

### Attachment and file-based threats

- Nissim, N., Cohen, A., Glezer, C., & Elovici, Y. (2015). Detection of malicious PDF files and directions for enhancements. *Computers & Security*. https://www.sciencedirect.com/science/article/pii/S0167404815000851

### LLM Security, Prompt Injection, and Practical Implementations

- Perez, F., & Ribeiro, I. (2022). Ignore previous prompt: Attack techniques for language models. *NeurIPS ML Safety Workshop*. https://arxiv.org/abs/2211.09527
- Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). Not what you have signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection. *AISec Workshop*. https://arxiv.org/abs/2302.12173
- Anthropic. (2024). *Claude's character and prompt injection resistance*. https://www.anthropic.com/research/claude-character
- Bar-Zik, R. (Internet Israel). *Basic LLM Security: Random Sequence Enclosure or SALT Prompt*. [Read Article](https://internet-israel.com/)
- Bar-Zik, R. (Internet Israel). *LLM as a Judge as a tool for verifying result reliability*. [Read Article](https://internet-israel.com/)
- Bar-Zik, R. (Internet Israel). *What is Indirect Prompt Injection?* [Read Article](https://internet-israel.com/%d7%a4%d7%99%d7%aa%d7%95%d7%97-%d7%90%d7%99%d7%a0%d7%98%d7%a8%d7%a0%d7%98/%d7%91%d7%a0%d7%99%d7%99%d7%aa-%d7%90%d7%aa%d7%a8%d7%99-%d7%90%d7%99%d7%a0%d7%98%d7%a8%d7%a0%d7%98-%d7%9c%d7%9e%d7%a4%d7%aa%d7%97%d7%99%d7%9d/%d7%90%d7%91%d7%98%d7%97%d7%aa-llm-%d7%9e%d7%94-%d7%96%d7%94-indirect-prompt-injection/)
