const nodemailer = require('nodemailer');
const appConfig = require('../config/appConfig');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  initializeTransporter() {
    // Use environment variables for email configuration
    const emailConfig = {
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASSWORD || ''
      }
    };

    // Only create transporter if credentials are provided
    if (emailConfig.auth.user && emailConfig.auth.pass) {
      this.transporter = nodemailer.createTransport(emailConfig);
      console.log('[Email Service] Transporter initialized');
    } else {
      console.warn('[Email Service] SMTP credentials not configured. Email verification will not work.');
      console.warn('[Email Service] Set SMTP_USER and SMTP_PASSWORD environment variables.');
    }
  }

  async sendVerificationCode(email, code, name) {
    if (!this.transporter) {
      throw new Error('Email service not configured. Please set SMTP_USER and SMTP_PASSWORD environment variables.');
    }

    const mailOptions = {
      from: `"File Box" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Verify Your Email - File Box',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #6366f1; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
            .code-box { background: white; border: 2px dashed #6366f1; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px; }
            .code { font-size: 32px; font-weight: bold; color: #6366f1; letter-spacing: 8px; font-family: monospace; }
            .footer { margin-top: 20px; font-size: 12px; color: #666; text-align: center; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>File Box</h1>
            </div>
            <div class="content">
              <h2>Hello ${name || 'there'}!</h2>
              <p>Thank you for signing up for File Box. Please verify your email address by entering the verification code below:</p>
              
              <div class="code-box">
                <div class="code">${code}</div>
              </div>
              
              <p>This code will expire in 10 minutes.</p>
              <p>If you didn't create an account with File Box, please ignore this email.</p>
            </div>
            <div class="footer">
              <p>© ${new Date().getFullYear()} File Box. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
        Hello ${name || 'there'}!
        
        Thank you for signing up for File Box. Please verify your email address by entering the verification code below:
        
        Verification Code: ${code}
        
        This code will expire in 10 minutes.
        
        If you didn't create an account with File Box, please ignore this email.
        
        © ${new Date().getFullYear()} File Box. All rights reserved.
      `
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log(`[Email Service] Verification email sent to ${email}:`, info.messageId);
      return { success: true, messageId: info.messageId };
    } catch (error) {
      console.error('[Email Service] Error sending email:', error);
      throw error;
    }
  }

  isConfigured() {
    return this.transporter !== null;
  }
}

module.exports = new EmailService();
