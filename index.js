const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Redis } = require('@upstash/redis');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Redis for Serverless (Credentials pulled from Vercel Env Vars)
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Production Security: Block IPs that request more than 5 OTPs in 15 minutes
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { success: false, message: 'Too many requests from this device. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Nodemailer setup using your App Password
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Health check endpoint for your Flutter app to verify server status
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'success', message: 'Everest Production API is healthy' });
});

// Send OTP Endpoint
app.post('/api/send-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ success: false, message: 'A valid email is required' });
  }

  // Generate a secure 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    // Save to Redis with an automatic expiration of 600 seconds (10 minutes)
    await redis.set(`otp:${email}`, otp, { ex: 600 });

    await transporter.sendMail({
      from: `"Everest Education" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Everest Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; text-align: center; color: #333;">
          <h2>Welcome to Everest!</h2>
          <p>Your email verification code is:</p>
          <h1 style="color: #2196F3; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
          <p>This code will expire in 10 minutes.</p>
        </div>
      `
    });

    res.status(200).json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Send OTP Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error while sending OTP' });
  }
});

// Verify OTP Endpoint
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required' });
  }

  try {
    // Fetch the OTP from Redis
    const storedOtp = await redis.get(`otp:${email}`);

    if (!storedOtp) {
      return res.status(400).json({ success: false, message: 'OTP expired or not found. Please request a new one.' });
    }

    if (String(storedOtp) === String(otp)) {
      // OTP matched. Delete it immediately so it cannot be reused.
      await redis.del(`otp:${email}`);
      return res.status(200).json({ success: true, message: 'Email verified successfully' });
    } else {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
  } catch (error) {
    console.error('Verify OTP Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during verification' });
  }
});

// Export the app so Vercel can wrap it in a Serverless Function
module.exports = app;