const pool = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { encrypt, decrypt } = require("../encryptionService");

const JWT_SECRET = "clave-super-segura"; // cambiar por variable de entorno

// 📌 REGISTRO DE USUARIO
async function register(req, res) {
  const { nombre_completo, usuario_id, email, contrasena, activo } = req.body;

  try {
    // --- 1. Separar nombre y apellido ---
    const partes = nombre_completo.trim().split(" ");
    const nombre = partes[0];
    const apellido = partes.slice(1).join(" ") || " "; // evitar null

    // --- 2. Hashear contraseña ---
    const contrasenaHash = await bcrypt.hash(contrasena, 10);

    // --- 3. Crear usuario normal ---
    await pool.query(
      `INSERT INTO usuarios (usuario_id, nombre_completo, email, contrasena_hash, rol_id, activo)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [usuario_id, nombre_completo, email, contrasenaHash, 3, activo]
    );

    // --- 4. Crear registro en tabla encriptada ---
    const fecha_registro = new Date();

    await pool.query(
      `INSERT INTO usuarios_encriptados (usuario_id, nombre_encriptado, email_encriptado, fecha_registro)
       VALUES ($1, $2, $3, $4)`,
      [usuario_id, encrypt(nombre_completo), encrypt(email), fecha_registro]
    );

    // --- 5. Generar código de estudiante ---
    const codigoEstudiante = `EST-${Date.now().toString().slice(-5)}`;

    // --- 6. Insertar en tabla estudiantes ---
    await pool.query(
      `INSERT INTO estudiantes (estudiante_id,nombre, apellido, email, titulacion_id, fecha_ingreso, codigo_estudiante)
       VALUES ($1, $2, $3, $4,$5, NOW(), $6)`,
      [usuario_id,nombre, apellido, email, 1, codigoEstudiante]
    );

    res.status(201).json({
      message: "Usuario y estudiante creados correctamente.",
      codigo_estudiante: codigoEstudiante
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al crear el usuario/estudiante." });
  }
}


// 📌 LOGIN
async function login(req, res) {
  const { email, contrasena } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM usuarios WHERE email = $1`, [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado." });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(contrasena, user.contrasena_hash);
    if (!isMatch) {
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

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

// 📌 OBTENER USUARIOS (DESCIFRADOS)
async function getUsuarios(req, res) {
  try {
    const result = await pool.query("SELECT * FROM usuarios_encriptados");

    const usuarios = result.rows.map((row) => ({
      usuario_encriptado_id: row.usuario_enc_id,
      nombre: decrypt(row.nombre_encriptado),
      usuario_id: row.usuario_id,
      email: decrypt(row.email_encriptado),
      fecha_registro: row.fecha_registro
    }));

    res.json(usuarios);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener usuarios." });
  }
}

module.exports = { register, login, getUsuarios };
