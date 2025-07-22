import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',  // example for Gmail SMTP
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER, // your SMTP email user
    pass: process.env.SMTP_PASS, // your SMTP email password or app password
  },
});

async function sendEmail({ sendTo, subject, html }) {
  const mailOptions = {
    from: `"Rilo Support" <${process.env.SMTP_USER}>`,
    to: sendTo,
    subject,
    html,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent: ", info.messageId);
    return info;
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
}

export default sendEmail;
