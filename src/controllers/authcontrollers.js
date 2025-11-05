const pool = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "clave-super-segura"; // 🔒 cámbiala por una variable de entorno

/* Registro de usuario
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
}*/

// Inicio de sesión
async function login(req, res) {
  const { email, contrasena } = req.body;

  try {
    // Buscar usuario por email (en la tabla usuarios)
    const result = await pool.query(
      `SELECT * FROM usuarios WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado." });
    }

    const user = result.rows[0];

    // Comparar contraseña ingresada con la almacenada
    const isMatch = await bcrypt.compare(contrasena, user.contrasena_hash);
    if (!isMatch) {
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

    // Generar token JWT
    const token = jwt.sign(
      { id: user.usuario_id, rol: user.rol_id },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Inicio de sesión exitoso.",
      token,
      usuario: {
        id: user.usuario_id,
        nombre: user.nombre_completo,
        email: user.email
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en el login." });
  }
}

module.exports = {  login };
