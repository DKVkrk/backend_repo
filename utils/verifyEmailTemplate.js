// utils/verifyEmailTemplate.js

export default function verifyEmailTemplate({ name, url }) {
    return `
        <div style="font-family: Arial, sans-serif;">
            <h2>Hello, ${name}</h2>
            <p>Thank you for registering. Please click the button below to verify your email address:</p>
            <a href="${url}" style="background-color:#007BFF;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Verify Email</a>
            <p>If the button doesn’t work, copy and paste the following URL into your browser:</p>
            <p>${url}</p>
        </div>
    `;
}
