const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const nodemailer = require("nodemailer");
require("dotenv").config();

const User = require("../models/User");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });

router.post("/register", upload.single("profileImage"), async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    const profileImage = req.file;

    if (!profileImage) {
      return res.status(400).send("No file uploaded");
    }

    const profileImagePath = profileImage.path;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists!" });
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      profileImagePath,
    });

    await newUser.save();

    res
      .status(200)
      .json({ message: "User registered successfully!", user: newUser });
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ message: "Registration failed!", error: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(409).json({ message: "User doesn't exist!" });
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Credentials!" })
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET)
    delete user.password

    const options = {
      expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
      httpOnly: true,
    }

    res.cookie("token", token, options).json({
      status: true,
      token, user, message: "Logged in successfully",
    })

    // res.status(200).json({ token, user });

  } catch (err) {
    console.log(err)
    res.status(500).json({ error: err.message })
  }
})



router.post("/forgot-password", async (req, res) => {
  try {

    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(409).json({ message: "User doesn't exist!" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "5m" });

    var transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      }
    });

    var mailOptions = {
      from: `"DreamHomes" ${process.env.MAIL_USER}`,
      to: `${email}`,
      subject: '[DreamHomes] Password Reset Link',
      text: `You're receiving this e-mail because you or someone else has requested a password reset for your user account at DreamHomes.

            Click the link below to reset your password:
            https://dreamhomes-3500.netlify.app/resetPassword/${token}`
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        return res.status(409).json({ message: "Error sending email" });
      } else {
        return res.status(200).json({
          message: "email sent successfully"
        });
      }
    });
  }
  catch (err) {
    console.log(err)
    res.status(500).json({ error: err.message })
  }
});



router.post("/reset-password/:token", async (req, res) => {
  try {

    const { token } = req.params;
    const { password } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded) {
      return res.status(401).json({
        message: "token is not valid"
      });
    }

    const id = decoded.id;

    const hashPassword = await bcrypt.hash(password, 10);
    const user = await User.findByIdAndUpdate({ _id: id }, { password: hashPassword });

    return res.status(200).json({
      user,
      message: "Password updated successfullly"
    })

  }
  catch (err) {
    console.log(err)
    res.status(500).json({ error: err.message })
  }
});

module.exports = router