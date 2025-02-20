require("dotenv").config(); // Load environment variables from .env file
const express = require("express"); // Import Express framework
const mysql = require("mysql2/promise"); // Import MySQL library with async/await support
const bcrypt = require("bcryptjs"); // Import bcrypt for password hashing
const jwt = require("jsonwebtoken"); // Import JWT for authentication
const cors = require("cors"); // Import CORS to handle cross-origin requests

const app = express(); // Create an Express application
app.use(express.json()); // Enable JSON parsing for request bodies
app.use(cors()); // Enable CORS for cross-origin requests

// Database connection configuration
const connection = mysql.createPool({
    host: "localhost", // Database host
    user: "root", // Database username
    password: "", // Database password (empty for local setups)
    database: "hamstech", // Database name
    waitForConnections: true, // Wait if all connections are busy
    connectionLimit: 10, // Max number of connections
    queueLimit: 0 // No limit on queueing requests
});

// Secret key for JWT authentication
const JWT_SECRET = process.env.JWT_SECRET || "hamtech";

// User registration route with default role "normal"
app.post("/register", async (req, res) => {
    const { name, email, password, rol = "normal" } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: "Missing data" });
    }
    if (!["admin", "normal"].includes(rol)) {
        return res.status(400).json({ error: "Invalid role" });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password before storing
        const [result] = await connection.execute(
            "INSERT INTO users (name, email, password, rol) VALUES (?, ?, ?, ?)",
            [name, email, hashedPassword, rol]
        );
        res.status(201).json({ message: "Registration successful", user: result.insertId });
    } catch (err) {
        console.error("Error in /register:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// User login route with JWT token including role
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Missing data" });
    }
    try {
        const [rows] = await connection.execute("SELECT * FROM users WHERE email = ?", [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: "User not found" });
        }
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password); // Compare input password with stored hash
        if (!match) {
            return res.status(401).json({ error: "Incorrect password" });
        }
        
        // Generate JWT token with user ID, email, and role
        const token = jwt.sign({ id: user.id, email: user.email, rol: user.rol }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful", token });
    } catch (err) {
        console.error("Error in /login:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Get user profile including role
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const [rows] = await connection.execute("SELECT id, name, email, rol FROM users WHERE id = ?", [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error("Error in /profile:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1]; // Extract token from Authorization header
    if (!token) return res.status(401).json({ message: "Access denied" });
    try {
        const verified = jwt.verify(token, JWT_SECRET); // Verify token validity
        req.user = verified; // Attach user data to request
        next(); // Proceed to next middleware or route handler
    } catch (err) {
        res.status(400).json({ message: "Invalid token" });
    }
}

const PORT = 3000; // Define server port
app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); // Start the server
