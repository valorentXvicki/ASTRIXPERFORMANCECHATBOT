const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = 'your-super-secret-jwt-key'; // <-- Use a strong, random secret
const GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID'; // <-- PASTE YOUR GOOGLE CLIENT ID
const GITHUB_CLIENT_ID = 'YOUR_GITHUB_CLIENT_ID'; // <-- PASTE YOUR GITHUB CLIENT ID
const GITHUB_CLIENT_SECRET = 'YOUR_GITHUB_CLIENT_SECRET'; // <-- PASTE YOUR GITHUB CLIENT SECRET

// Database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",        // change this
  password: "password",// change this
  database: "athletic_spirit"
});

// Sign Up (Save user)
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (username, email, password, googleId) VALUES (?, ?, ?, NULL)", // googleId is NULL for local signup
    [username, email, hashedPassword], // Pass NULL for googleId
    (err) => {
      if (err) {
        console.error("Signup error:", err);
        return res.status(500).json({ error: err.sqlMessage || "Error registering user." });
      }
      res.json({ message: "User registered successfully!" });
    }
  );
});

// Login (Check user)
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.sqlMessage });
    if (results.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const user = results[0];
    // Ensure user has a password before comparing (for social-only accounts)
    if (!user.password) {
      return res.status(401).json({ error: "Please log in using your social account." });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });
      res.json({ message: "Login successful", token });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  });
});

// --- Google Login ---
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
app.post('/auth/google', async (req, res) => {
  const { id_token } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({
        idToken: id_token,
        audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    db.query("SELECT * FROM users WHERE googleId = ? OR email = ?", [googleId, email], (err, results) => {
      if (err) return res.status(500).json({ error: "Database error during Google login." });

      let user = results[0];
      if (user) { // User exists
        // If user exists by email but googleId is null, update it
        if (!user.googleId) {
          db.query("UPDATE users SET googleId = ? WHERE id = ?", [googleId, user.id]);
        }
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });
        return res.json({ message: "Google login successful!", token });
      } else { // New user
        const username = name || email.split('@')[0];
        db.query("INSERT INTO users (username, email, googleId) VALUES (?, ?, ?)", [username, email, googleId], (err, insertResult) => {
          if (err) return res.status(500).json({ error: "Failed to create user from Google account." });
          const token = jwt.sign({ userId: insertResult.insertId }, JWT_SECRET, { expiresIn: '1d' });
          return res.json({ message: "Google account registered and logged in!", token });
        });
      }
    });
  } catch (error) {
    console.error("Google token verification failed:", error);
    res.status(401).json({ error: "Invalid Google token." });
  }
});

// --- GitHub Login ---

// 1. Redirect user to GitHub's authorization page
app.get('/auth/github', (req, res) => {
  const url = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email`;
  res.redirect(url);
});

// 2. GitHub redirects back here with a code
app.get('/auth/github/callback', async (req, res) => {
  const { code } = req.query;
  try {
    // Exchange code for an access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code: code,
    }, { headers: { 'Accept': 'application/json' } });
    const accessToken = tokenResponse.data.access_token;

    // Use access token to get user info
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: { 'Authorization': `token ${accessToken}` }
    });
    const { id: githubId, login: username, email: publicEmail } = userResponse.data;

    let email = publicEmail;
    // If email is null, fetch private emails
    if (!email) {
      const emailResponse = await axios.get('https://api.github.com/user/emails', {
        headers: { 'Authorization': `token ${accessToken}` }
      });
      const primaryEmail = emailResponse.data.find(e => e.primary && e.verified);
      email = primaryEmail ? primaryEmail.email : null;
    }

    if (!email) {
      return res.status(400).send('Could not retrieve a verified email from GitHub. Please set a public email on your GitHub profile.');
    }

    // Now, find or create user in your DB (similar to Google logic)
    // ... (logic to find/create user and generate JWT)

    // For now, redirect to the frontend with a message (a real app would pass a token)
    // A more advanced flow would pass the JWT back to the frontend via query params or postMessage
    res.send(`<script>
      alert('GitHub login successful! This is where you would receive a token.');
      window.close(); // Close the popup
    </script>`);

  } catch (error) {
    console.error('GitHub auth error:', error.response ? error.response.data : error.message);
    res.status(500).send('An error occurred during GitHub authentication.');
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
