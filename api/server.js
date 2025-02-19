require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// Configuración de conexión a la base de datos
const connection = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "hamstech",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || "hamtech";

// Registro de usuario
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: "Faltan datos" });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await connection.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );
        res.status(201).json({ message: "Registro exitoso", user: result.insertId });
    } catch (err) {
        console.error("Error en /register:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Inicio de sesión
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Faltan datos" });
    }
    try {
        const [rows] = await connection.execute("SELECT * FROM users WHERE email = ?", [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: "Usuario no encontrado" });
        }
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: "Contraseña incorrecta" });
        }
        
        // Generar token
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Inicio de sesión exitoso", token });
    } catch (err) {
        console.error("Error en /login:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Perfil del usuario
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const [rows] = await connection.execute("SELECT id, name, email FROM users WHERE id = ?", [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error("Error en /profile:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Middleware para verificar el token
function verifyToken(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Acceso denegado" });
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: "Token inválido" });
    }
}

const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
