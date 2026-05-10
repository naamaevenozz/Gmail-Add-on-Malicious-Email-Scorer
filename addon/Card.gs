/**
 * Card.gs - Gmail Add-on UI
 */

// Contextual trigger - entry point called by Gmail on message open
function onEmailOpen(e) {
  try {
    const messageId = e.gmail && e.gmail.messageId;
    if (!messageId) return buildSkipCard();

    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    const message = GmailApp.getMessageById(messageId);

    // 1. Exclude Drafts natively
    if (message.isDraft()) {
      return buildSkipCard();
    }

    // 2. Exclude Sent emails (by checking if the user is the sender)
    const sender = message.getFrom().toLowerCase();
    let myEmails = [Session.getActiveUser().getEmail().toLowerCase()];

    // Safely include any aliases the user might send from
    try {
      const aliases = GmailApp.getAliases().map(a => a.toLowerCase());
      myEmails = myEmails.concat(aliases);
    } catch (aliasErr) {
      // Ignore if alias scope is missing, fallback to primary email
    }

    const isSentByMe = myEmails.some(email => sender.includes(email));

    if (isSentByMe) {
      return buildSkipCard();
    }

    // Proceed with analysis only for incoming emails
    const emailData = extractEmailData(messageId);
    const result    = analyzeEmail(emailData);

    if (!result || result.error) {
      const msg = result ? result.message : 'Unknown error.';
      return buildErrorCard(result ? result.code : 500, msg);
    }
    return buildVerdictCard(result);

  } catch (err) {
    // Switched to console.error to leverage your STACKDRIVER logging
    console.error('onEmailOpen exception: ' + err.message);
    return buildErrorCard(500, 'Unexpected error. Please reload.');
  }
}
// Card builder

function buildVerdictCard(verdict) {
  var card = CardService.newCardBuilder()
    .setName('emailRiskScorer')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Email Risk Scorer')
        .setSubtitle('Layered security assessment')
        .setImageUrl('https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png')
    );

  card.addSection(buildRiskHeaderSection(verdict));

  var hasReasoning = verdict.llm_reasoning && verdict.llm_reasoning.indexOf('[Layer 4') === -1;
  if (hasReasoning) {
    card.addSection(buildReasoningSection(verdict));
  }

  if (verdict.triggered_signals && verdict.triggered_signals.length > 0) {
    card.addSection(buildFindingsSection(verdict.triggered_signals));
  }

  card.addSection(buildActionSection(verdict));

  return card.build();
}

// Section 1 — Risk header

var VERDICT_META = {
  'MALICIOUS':  { icon: '🔴', label: 'MALICIOUS',  color: '#C62828' },
  'SUSPICIOUS': { icon: '🟠', label: 'SUSPICIOUS', color: '#E65100' },
  'LOW_RISK':   { icon: '🟡', label: 'LOW RISK',   color: '#F9A825' },
  'SAFE':       { icon: '🟢', label: 'SAFE',       color: '#2E7D32' }
};

function buildRiskHeaderSection(verdict) {
  var meta  = VERDICT_META[verdict.verdict] || { icon: '⚪', label: verdict.verdict };
  var section = CardService.newCardSection();

  section.addWidget(
    CardService.newTextParagraph()
      .setText('<b><font size="20">' + meta.icon + ' ' + meta.label + '</font></b>')
  );

  section.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Risk Score')
      .setContent('<b>' + verdict.score + ' / 100</b>')
      .setBottomLabel('Confidence: ' + verdict.confidence)
  );

  return section;
}

// Section 2 — Findings

function buildFindingsSection(signals) {
  var section = CardService.newCardSection().setHeader('🔎 What We Found');

  for (var i = 0; i < signals.length; i++) {
    section.addWidget(
      CardService.newTextParagraph().setText('• ' + signals[i].label)
    );
  }

  return section;
}

// Section 3 — LLM reasoning

function buildReasoningSection(verdict) {
  var section = CardService.newCardSection().setHeader('🔍 Analysis');

  section.addWidget(
    CardService.newTextParagraph().setText(verdict.llm_reasoning)
  );

  return section;
}

// Section 4 — Recommended action

function buildActionSection(verdict) {
  var section = CardService.newCardSection().setHeader('Recommended Action');

  section.addWidget(
    CardService.newTextParagraph().setText(verdict.recommended_action)
  );

  if (verdict.verdict === 'MALICIOUS' || verdict.verdict === 'SUSPICIOUS') {
    section.addWidget(
      CardService.newButtonSet()
        .addButton(
          CardService.newTextButton()
            .setText('Report as Phishing')
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
            .setOnClickAction(CardService.newAction().setFunctionName('handleReportPhishing'))
        )
        .addButton(
          CardService.newTextButton()
            .setText('Mark Safe')
            .setOnClickAction(CardService.newAction().setFunctionName('handleMarkSafe'))
        )
    );
  }

  section.addWidget(
    CardService.newTextParagraph()
      .setText('<font color="#9E9E9E">Analysis completed in ' + verdict.processing_ms + ' ms</font>')
  );

  return section;
}

// Button handlers

function handleReportPhishing(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText('Reported. Thank you for helping keep your inbox safe.')
    )
    .build();
}

function handleMarkSafe(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText('Marked as safe.')
    )
    .build();
}

// Utility cards

function buildSkipCard() {
  return CardService.newCardBuilder()
    .setName('skip')
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText('Analysis is only available for incoming emails.')
        )
    )
    .build();
}

function buildErrorCard(code, message) {
  var label = code === 429 ? '⏳ Rate Limited' : code === 0 ? '📡 Connection Error' : '⚠️ Analysis Error';

  return CardService.newCardBuilder()
    .setName('error')
    .setHeader(CardService.newCardHeader().setTitle('Email Risk Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText('<b>' + label + '</b><br><br>' + (message || ''))
        )
        .addWidget(
          CardService.newButtonSet()
            .addButton(
              CardService.newTextButton()
                .setText('Retry')
                .setOnClickAction(CardService.newAction().setFunctionName('onEmailOpen'))
            )
        )
    )
    .build();
}