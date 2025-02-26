require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const connection = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "hamstech",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || "hamtech";
const loginAttempts = {};

app.post("/register", async (req, res) => {
    const { name, email, password, rol = "normal" } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: "Missing data" });
    }
    if (!["admin", "normal"].includes(rol)) {
        return res.status(400).json({ error: "Invalid role" });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
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

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Missing data" });
    }
    try {
        if (loginAttempts[email] && loginAttempts[email].attempts >= 3) {
            const timeDiff = (Date.now() - loginAttempts[email].time) / 1000;
            if (timeDiff < 300) {
                return res.status(403).json({ error: "Too many attempts. Try again in 5 minutes." });
            } else {
                delete loginAttempts[email];
            }
        }

        const [rows] = await connection.execute("SELECT * FROM users WHERE email = ?", [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: "User not found" });
        }
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            loginAttempts[email] = loginAttempts[email] || { attempts: 0, time: Date.now() };
            loginAttempts[email].attempts++;
            return res.status(401).json({ error: "Incorrect password" });
        }

        delete loginAttempts[email];

        const token = jwt.sign({ id: user.id, email: user.email, rol: user.rol }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful", token, dashboard: `/dashboard/${user.rol}` });
    } catch (err) {
        console.error("Error in /login:", err);
        res.status(500).json({ error: "Server error" });
    }
});

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


function verifyToken(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access denied" });
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: "Invalid token" });
    }
}
app.get("/users", async (req, res) => {
    try {
        const [rows] = await connection.execute("SELECT id, name, email, rol FROM users");
        if (rows.length === 0) {
            return res.status(404).json({ error: "No users found" });
        }
        res.json(rows); // Send all users
    } catch (err) {
        console.error("Error in /users:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.delete("/users/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await connection.execute("DELETE FROM users WHERE id = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.status(200).json({ message: "User deleted successfully" });
    } catch (err) {
        console.error("Error in /users/:id delete:", err);
        res.status(500).json({ error: "Server error" });
    }
});



const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
