
const nodemailer = require("nodemailer");

const emailUser = process.env.ADMIN_EMAIL_USER;
const emailAppPassword = process.env.ADMIN_EMAIL_APP_PASSWORD;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };

    return entities[character];
  });
}

async function sendVerificationEmail(email, code, name) {
  if (!emailUser || !emailAppPassword) {
    throw new Error(
      "Gmail credentials are missing. Check your backend .env file."
    );
  }

  if (!/^\d{6}$/.test(String(code))) {
    throw new Error("The verification code must contain six digits.");
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: emailUser,
      pass: emailAppPassword,
    },
  });

  const safeName = escapeHtml(name);
  const safeCode = escapeHtml(code);

  await transporter.sendMail({
    from: `"Ikuzwe Restaurant" <${emailUser}>`,
    to: email,
    subject: "Verify your Ikuzwe Restaurant admin account",

    text: `Hello ${name},

Your email verification code is: ${code}

Enter this code to verify your admin account.

This code expires in 10 minutes. If you did not request this account, you can ignore this email.

Ikuzwe Restaurant`,

    html: `
      <div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; padding: 28px; color: #191a1d; border: 1px solid #e9e7e1; border-radius: 14px;">
        <h1 style="color: #c99200; margin-bottom: 8px;">Ikuzwe Restaurant</h1>
        <h2>Verify your admin email</h2>
        <p>Hello ${safeName},</p>
        <p>Enter the verification code below to activate your admin account:</p>
        <div style="padding: 18px; margin: 22px 0; text-align: center; background: #faf8f2; border-radius: 10px;">
          <strong style="font-size: 32px; letter-spacing: 8px;">${safeCode}</strong>
        </div>
        <p>This code expires in <strong>10 minutes</strong>.</p>
        <p>If you did not request this account, you can ignore this email.</p>
        <hr style="border: 0; border-top: 1px solid #e9e7e1; margin: 24px 0;" />
        <p style="color: #747474; font-size: 12px;">Ikuzwe Restaurant · Admin Security</p>
      </div>
    `,
  });
}

module.exports = sendVerificationEmail;
