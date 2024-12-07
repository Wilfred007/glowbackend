const router = require("express").Router();
const User = require("../models/Users");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");

//REGISTER
router.post("/register", async (req, res) => {
  console.log(req.body)
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: CryptoJS.AES.encrypt(req.body.password, process.env.PASS_SECRET_KEY).toString(),
  });

  

  try {
    const savedUser = await newUser.save();
    res.status(201).json(savedUser);
  } catch (err) {
    res.status(500).json(err);
  }
});

//LOGIN

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json("Username and password are required");
    }

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json("Wrong Credentials");

    const hashedPassword = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASS_SECRET_KEY
    );
    const OriginalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);

    if (OriginalPassword !== password) {
      return res.status(401).json("Wrong Credentials");
    }

    const accessToken = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    const { password: userPassword, ...others } = user._doc; // Correct destructuring

    res.status(200).json({ ...others, accessToken });
  } catch (err) {
    console.error("Login Error:", err); // Log error details
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});

module.exports = router;
