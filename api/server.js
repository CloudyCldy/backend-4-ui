require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const xlsx = require("xlsx");

const app = express();
app.use(express.json());
app.use(cors());

const upload = multer({ storage: multer.memoryStorage() });

const connection = mysql.createPool({
    host: "34.224.75.233",           // IP de la EC2
    user: "admin",                    // Usuario
    password: "hobito22",             // Contraseña
    database: "hamstech",             // Nombre de la base de datos
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

// Ruta para importar un archivo Excel
app.post("/import-excel", upload.single("file"), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
    }

    try {
        const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);

        if (data.length === 0) {
            return res.status(400).json({ error: "Empty Excel file" });
        }

        const sql = "INSERT INTO users (id, name, email, rol, password) VALUES ?";
        const values = data.map(row => [row.id, row.name, row.email, row.rol, row.password]);

        const [result] = await connection.query(sql, [values]);

        res.json({ message: "Data imported successfully", insertedRows: result.affectedRows });
    } catch (error) {
        console.error("Error processing Excel:", error);
        res.status(500).json({ error: "Failed to process Excel file" });
    }
});

// Ruta para guardar datos del sensor
app.post("/sensor-data", async (req, res) => {
    const { device_id, temperature, humidity } = req.body;

    if (!device_id || !temperature || !humidity) {
        return res.status(400).json({ error: "Missing fields" });
    }

    try {
        const [result] = await connection.execute(
            "INSERT INTO sensor_readings (device_id, temperature, humidity) VALUES (?, ?, ?)",
            [device_id, parseFloat(temperature), parseFloat(humidity)]
        );

        console.log(`Datos guardados: Device: ${device_id}, Temp: ${temperature}C, Hum: ${humidity}%`);
        res.status(201).json({ message: "Data saved successfully", id: result.insertId });

    } catch (error) {
        console.error("Error saving data:", error);
        res.status(500).json({ error: "Server error" });
    }
});

// Puerto EC2
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en ${PORT}`));
