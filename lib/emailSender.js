// Email sending via Resend
// Sends invitation emails and other transactional emails

const { Resend } = require("resend");

// Simple logging helper
function logEmailEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "email_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Initialize Resend client (singleton)
let resendClient = null;

function getResendClient() {
  if (resendClient) {
    return resendClient;
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    logEmailEvent("warn", "email_sender_config_missing", {
      note: "RESEND_API_KEY not configured - email sending disabled",
    });
    return null;
  }

  try {
    resendClient = new Resend(apiKey);
    return resendClient;
  } catch (error) {
    logEmailEvent("error", "email_sender_init_error", {
      error: error?.message || String(error),
      note: "Failed to initialize Resend client",
    });
    return null;
  }
}

// Helper to escape HTML (simple implementation)
function escapeHtml(text) {
  if (typeof text !== "string") {
    return String(text);
  }
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Send invitation email via Resend
// This is a side effect - failures do not block invitation creation
// Returns: { success: boolean, error?: string }
// baseUrl: base URL for acceptance link (e.g., "https://app.example.com")
async function sendInvitationEmail({ to, client_id, invite_id, token, baseUrl = null, requestId = null }) {
  const client = getResendClient();
  if (!client) {
    logEmailEvent("warn", "email_invitation_not_sent", {
      requestId: requestId,
      to: to,
      clientId: client_id,
      inviteId: invite_id,
      reason: "email_sender_not_configured",
      note: "RESEND_API_KEY not set - invitation created but email not sent",
    });
    return { success: false, error: "Email sender not configured" };
  }

  try {
    // Free Resend plan requires sending from onboarding@resend.dev
    const fromEmail = "onboarding@resend.dev";
    const subject = "Welcome to ClientPulse onboarding";

    // Construct acceptance URL
    // Prefer provided baseUrl, then env vars, then fallback
    const effectiveBaseUrl = baseUrl || process.env.BASE_URL || process.env.APP_URL || "https://your-app-url.com";
    const acceptanceUrl = `${effectiveBaseUrl}/admin/invitations/accept?token=${encodeURIComponent(token)}`;

    // Escape client_id and URL for HTML safety
    const escapedClientId = escapeHtml(client_id);
    const escapedUrl = escapeHtml(acceptanceUrl);

    // HTML email body with acceptance link
    const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
    .content { padding: 20px 0; }
    .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 4px; margin: 20px 0; }
    .button:hover { background-color: #0056b3; }
    .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2>Welcome to ClientPulse</h2>
    </div>
    <div class="content">
      <p>Hello,</p>
      <p>You have been invited to manage the client configuration for <strong>${escapedClientId}</strong>.</p>
      <p>To get started, please click the button below to accept your invitation and set up your account:</p>
      <p style="text-align: center;">
        <a href="${escapedUrl}" class="button">Accept Invitation</a>
      </p>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all; color: #666; font-size: 12px;">${escapedUrl}</p>
      <p><strong>Important:</strong> This invitation will expire in 7 days.</p>
      <p>If you have any questions, please contact support at support@example.com.</p>
    </div>
    <div class="footer">
      <p>This is an automated message. Please do not reply to this email.</p>
    </div>
  </div>
</body>
</html>
    `.trim();

    // Plain text fallback
    const textBody = `
Welcome to ClientPulse

Hello,

You have been invited to manage the client configuration for ${client_id}.

To get started, please accept your invitation by visiting this link:

${acceptanceUrl}

Important: This invitation will expire in 7 days.

If you have any questions, please contact support at support@example.com.

---
This is an automated message. Please do not reply to this email.
    `.trim();

    const { data, error } = await client.emails.send({
      from: fromEmail,
      to: to,
      subject: subject,
      html: htmlBody,
      text: textBody,
    });

    if (error) {
      logEmailEvent("warn", "email_invitation_failed", {
        requestId: requestId,
        to: to,
        clientId: client_id,
        inviteId: invite_id,
        error: error?.message || String(error),
        errorCode: error?.name || null,
        note: "Invitation created in database, but email delivery failed",
      });
      return { success: false, error: error?.message || String(error) };
    }

    logEmailEvent("info", "email_invitation_sent", {
      requestId: requestId,
      to: to,
      clientId: client_id,
      inviteId: invite_id,
      emailId: data?.id || null,
      note: "Invitation email sent successfully via Resend",
    });

    return { success: true, emailId: data?.id || null };
  } catch (error) {
    logEmailEvent("warn", "email_invitation_error", {
      requestId: requestId,
      to: to,
      clientId: client_id,
      inviteId: invite_id,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
      note: "Invitation created in database, but email sending encountered an error",
    });
    return { success: false, error: error?.message || String(error) };
  }
}

module.exports = {
  sendInvitationEmail,
  getResendClient,
  logEmailEvent,
};

