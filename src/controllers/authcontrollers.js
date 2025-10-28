const pool = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;

// Registro de usuario
async function register(req, res) {
  const { nombre, email, contrasena, rol } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(contrasena, 10);
    await pool.query(
      `INSERT INTO usuarios (nombre, email, contrasena, rol)
       VALUES ($1, $2, $3, $4)`,
      [nombre, email, hashedPassword, rol]
    );
    res.status(201).json({ message: "Usuario registrado correctamente." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al registrar usuario." });
  }
}

// Inicio de sesión
async function login(req, res) {
  const { email, contrasena } = req.body;
  try {
    const result = await pool.query(`SELECT * FROM usuarios WHERE email = $1`, [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado." });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(contrasena, user.contrasena);
    if (!isMatch) {
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

    const token = jwt.sign(
      { id: user.id, rol: user.rol },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({ message: "Inicio de sesión exitoso.", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en el login." });
  }
}

module.exports = { register, login };
