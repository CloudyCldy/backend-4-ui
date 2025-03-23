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
        res.json(rows);
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

// Ruta para importar un archivo Excel a la base de datos
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

        const sql = "INSERT INTO users (id,name, email,rol, password) VALUES ?";
        const values = data.map(row => [row.id, row.name, row.email, row.rol, row.password]);

        const [result] = await connection.query(sql, [values]);

        res.json({ message: "Data imported successfully", insertedRows: result.affectedRows });
    } catch (error) {
        console.error("Error processing Excel:", error);
        res.status(500).json({ error: "Failed to process Excel file" });
    }
});


// Ruta para obtener todos los hamsters
app.get("/hamsters", async (req, res) => {
    try {
        const [rows] = await connection.execute("SELECT * FROM hamsters");
        if (rows.length === 0) {
            return res.status(404).json({ error: "No hamsters found" });
        }
        res.json(rows);
    } catch (err) {
        console.error("Error in /hamsters:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.get("/hamsters/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await connection.execute("SELECT * FROM hamsters WHERE id = ?", [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: "Hamster not found" });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error("Error in /hamsters/:id:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/hamsters", async (req, res) => {
    const { user_id, name, breed, age, weight, health_notes, device_id } = req.body;
    if (!name || !breed || !age || !weight) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        const [result] = await connection.execute(
            "INSERT INTO hamsters (user_id, name, breed, age, weight, health_notes, device_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [user_id, name, breed, age, weight, health_notes, device_id]
        );
        res.status(201).json({ message: "Hamster created successfully", hamsterId: result.insertId });
    } catch (err) {
        console.error("Error in /hamsters:", err);
        res.status(500).json({ error: "Server error" });
    }
});

app.put("/hamsters/:id", async (req, res) => {
    const { id } = req.params;
    const { name, breed, age, weight, health_notes, device_id, user_id } = req.body;

    if (!name || !breed || !age || !weight || !device_id || !user_id) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        // Verificar si el usuario existe
        const [userCheck] = await connection.execute(
            "SELECT id FROM users WHERE id = ?",
            [user_id]
        );
        if (userCheck.length === 0) {
            return res.status(400).json({ error: "User ID not found" });
        }

        // Verificar si el dispositivo existe
        const [deviceCheck] = await connection.execute(
            "SELECT id FROM devices WHERE id = ?",
            [device_id]
        );
        if (deviceCheck.length === 0) {
            return res.status(400).json({ error: "Device ID not found" });
        }

        const [result] = await connection.execute(
            "UPDATE hamsters SET name = ?, breed = ?, age = ?, weight = ?, health_notes = ?, device_id = ?, user_id = ? WHERE id = ?",
            [name, breed, age, weight, health_notes, device_id, user_id, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Hamster not found" });
        }

        res.json({ message: "Hamster updated successfully" });
    } catch (err) {
        console.error("Error in /hamsters/:id:", err);
        res.status(500).json({ error: "Server error" });
    }
});


app.delete("/hamsters/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await connection.execute("DELETE FROM hamsters WHERE id = ?", [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Hamster not found" });
        }
        res.status(200).json({ message: "Hamster deleted successfully" });
    } catch (err) {
        console.error("Error in /hamsters/:id delete:", err);
        res.status(500).json({ error: "Server error" });
    }
});



// Ruta para obtener todos los registros
// Ruta para obtener todos los dispositivos
app.get("/devices", async (req, res) => {
    try {
        const [rows] = await connection.execute("SELECT * FROM devices");
        if (rows.length === 0) {
            return res.status(404).json({ error: "No devices found" });
        }
        res.json(rows);
    } catch (err) {
        console.error("Error in /devices:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Ruta para obtener un registro por su ID
app.get("/devices/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await connection.execute("SELECT * FROM devices WHERE id = ?", [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: "Device not found" });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error("Error in /devices/:id:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Ruta para agregar un nuevo dispositivo
app.post("/devices", async (req, res) => {
    const { name, type, model } = req.body;
    try {
        const [result] = await connection.execute(
            "INSERT INTO devices (name, type, model) VALUES (?, ?, ?)",
            [name, type, model]
        );
        res.status(201).json({ message: "Device added successfully", deviceId: result.insertId });
    } catch (err) {
        console.error("Error in /devices (POST):", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Ruta para editar un dispositivo por su ID
app.put("/devices/:id", async (req, res) => {
    const { id } = req.params;
    const { name, type, model } = req.body;
    try {
        const [result] = await connection.execute(
            "UPDATE devices SET name = ?, type = ?, model = ? WHERE id = ?",
            [name, type, model, id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Device not found" });
        }
        res.json({ message: "Device updated successfully" });
    } catch (err) {
        console.error("Error in /devices/:id (PUT):", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Ruta para eliminar un dispositivo por su ID
app.delete("/devices/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await connection.execute("DELETE FROM devices WHERE id = ?", [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Device not found" });
        }
        res.json({ message: "Device deleted successfully" });
    } catch (err) {
        console.error("Error in /devices/:id (DELETE):", err);
        res.status(500).json({ error: "Server error" });
    }
});


// Ruta vacía para el blog
app.get("/blog", async (req, res) => {
    res.json({ message: "Blog page - No content yet" });
});


app.post("/sensor-data", async (req, res) => {
    const { device_id, temperature, humidity } = req.body;

    if (!device_id || !temperature || !humidity) {
        return res.status(400).json({ error: "Missing fields" });
    }

    try {
        // ✅ Asegúrate de que la API los guarde como decimales
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



const PORT = 3000;
app.listen(PORT, () => console.log(`ya jalo ${PORT}`));
