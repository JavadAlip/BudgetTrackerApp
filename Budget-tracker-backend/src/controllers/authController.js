const User = require('../models/user');
const sendEmail = require('../utils/sendEmail');
const generateOtp = require('../utils/generateOtp');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.registerUser = async (req, res) => {
  try {
    const { name, email } = req.body;

    // 1. Basic validation
    if (!name || !email) {
      return res.status(400).json({
        message: 'Name and email are required',
      });
    }

    // 2. Check existing user
    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({
        message: 'User already registered. Please login.',
      });
    }

    // 3. Generate OTP
    const otp = generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    let user;

    if (existingUser) {
      // Update OTP for unverified user
      user = existingUser;
      user.otp = otp;
      user.otpExpiry = otpExpiry;
    } else {
      // Create new user
      user = new User({
        name,
        email,
        otp,
        otpExpiry,
        isVerified: false,
      });
    }

    // 4. Save user
    await user.save();

    // 5. Send OTP email (with proper logging)
    try {
      await sendEmail(
        email,
        'OTP Verification - Money Saver App',
        `
          <div style="font-family: Arial, sans-serif">
            <h2>Money Saver App</h2>
            <p>Your OTP is:</p>
            <h1 style="letter-spacing: 4px;">${otp}</h1>
            <p>This OTP is valid for <b>10 minutes</b>.</p>
          </div>
        `
      );

      console.log('✅ OTP email sent successfully to:', email);
    } catch (mailError) {
      console.error('❌ Email sending failed:', mailError);

      return res.status(500).json({
        message: 'Failed to send OTP email. Please try again later.',
      });
    }

    // 6. Final response
    return res.status(200).json({
      message: 'OTP sent to your email',
    });
  } catch (error) {
    console.error('❌ Register error:', error);

    return res.status(500).json({
      message: 'Server error',
    });
  }
};

exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // 1. Validation
    if (!email || !otp) {
      return res.status(400).json({
        message: 'Email and OTP are required',
      });
    }

    // 2. Find user
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    // 3. Already verified check
    if (user.isVerified) {
      return res.status(400).json({
        message: 'User already verified',
      });
    }

    // 4. OTP match check
    if (user.otp !== otp) {
      return res.status(400).json({
        message: 'Invalid OTP',
      });
    }

    // 5. OTP expiry check
    if (user.otpExpiry < new Date()) {
      return res.status(400).json({
        message: 'OTP has expired',
      });
    }

    // 6. Mark user as verified
    user.isVerified = true;
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    return res.status(200).json({
      message: 'Email verified successfully',
    });
  } catch (error) {
    console.error('Verify OTP error:', error);

    return res.status(500).json({
      message: 'Server error',
    });
  }
};

exports.setPassword = async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    // 1. Validation
    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: 'Password must be at least 6 characters' });
    }

    // 2. Find user
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Email not verified' });
    }

    if (user.password) {
      return res
        .status(400)
        .json({ message: 'Password already set. Please login.' });
    }

    // 3. Hash password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    return res.status(200).json({
      message: 'Password created successfully. Please login.',
    });
  } catch (error) {
    console.error('Set password error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validation
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: 'Email and password are required' });
    }

    // 2. Find user
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res
        .status(403)
        .json({ message: 'Please verify your email first' });
    }

    if (!user.password) {
      return res
        .status(400)
        .json({ message: 'Password not set. Please create password.' });
    }

    // 3. Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 4. Generate JWT
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' } // you can change
    );

    return res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not registered' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Email not verified' });
    }

    const otp = generateOtp();
    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await user.save();

    await sendEmail(
      email,
      'Reset Password OTP - Money Saver App',
      `<h2>Your password reset OTP is: ${otp}</h2><p>Valid for 10 minutes.</p>`
    );

    return res.status(200).json({
      message: 'OTP sent to registered email',
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.verifyForgotOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (user.otpExpiry < new Date()) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    return res.status(200).json({
      message: 'OTP verified successfully',
    });
  } catch (error) {
    console.error('Verify forgot OTP error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: 'Password must be at least 6 characters' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const bcrypt = require('bcryptjs');
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // clear OTP
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    return res.status(200).json({
      message: 'Password reset successful. Please login.',
    });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};
