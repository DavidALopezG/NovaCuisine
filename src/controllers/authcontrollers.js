const pool = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { encrypt, decrypt } = require("../encryptionService");
const { requireEnv } = require("../config/env");
const { normalizarEmail, emailValido, cedulaEcuatorianaValida, contrasenaValida } = require("../utils/validaciones");

require("dotenv").config();
const JWT_SECRET = requireEnv("JWT_SECRET"); // antes tenía un valor hardcodeado aquí

// 📌 REGISTRO DE USUARIO
async function register(req, res) {
  const { nombre_completo, usuario_id, contrasena } = req.body;
  const email = normalizarEmail(req.body.email);

  // Validaciones de entrada (esta ruta es pública)
  if (!nombre_completo || String(nombre_completo).trim().length < 3 || String(nombre_completo).length > 100) {
    return res.status(400).json({ error: "El nombre completo es obligatorio (3 a 100 caracteres)." });
  }
  if (!cedulaEcuatorianaValida(usuario_id)) {
    return res.status(400).json({ error: "La cédula ingresada no es válida." });
  }
  if (!emailValido(email)) {
    return res.status(400).json({ error: "El correo electrónico no es válido." });
  }
  if (!contrasenaValida(contrasena)) {
    return res.status(400).json({ error: "La contraseña debe tener mínimo 8 caracteres, con letras y números." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const partes = nombre_completo.trim().split(/\s+/);
    const nombre = partes[0];
    const apellido = partes.slice(1).join(" ") || " ";
    const contrasenaHash = await bcrypt.hash(contrasena, 10);

    // Autorregistro: SIEMPRE rol Estudiante (3) y activo = true; no se acepta "activo" del body
    await client.query(
      `INSERT INTO usuarios (usuario_id, nombre_completo, email, contrasena_hash, rol_id, activo)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [usuario_id, nombre_completo.trim(), email, contrasenaHash, 3, true]
    );

    await client.query(
      `INSERT INTO usuarios_encriptados (usuario_id, nombre_encriptado, email_encriptado, fecha_registro)
       VALUES ($1, $2, $3, $4)`,
      [usuario_id, encrypt(nombre_completo.trim()), encrypt(email), new Date()]
    );

    const codigoEstudiante = `EST-${Date.now().toString().slice(-5)}${Math.floor(Math.random() * 90 + 10)}`;

    await client.query(
      `INSERT INTO estudiantes (estudiante_id, usuario_id, nombre, apellido, email, titulacion_id, fecha_ingreso, codigo_estudiante, cedula)
       VALUES ($1, $1, $2, $3, $4, $5, NOW(), $6, $1)`,
      [usuario_id, nombre, apellido, email, 1, codigoEstudiante]
    );

    await client.query("COMMIT");

    res.status(201).json({
      message: "Usuario y estudiante creados correctamente.",
      codigo_estudiante: codigoEstudiante
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("🔴 register:", err.message);
    if (err.code === "23505") {
      if (err.detail && err.detail.includes("email")) {
        return res.status(409).json({ error: "Ya existe una cuenta con ese correo electrónico." });
      }
      if (err.detail && err.detail.toLowerCase().includes("codigo")) {
        return res.status(409).json({ error: "No se pudo generar el código de estudiante, intenta de nuevo." });
      }
      return res.status(409).json({ error: "Ya existe una cuenta registrada con esa cédula." });
    }
    res.status(500).json({ error: "Error al crear el usuario/estudiante." });
  } finally {
    client.release();
  }
}


// 📌 LOGIN
async function login(req, res) {
  const email = normalizarEmail(req.body.email);
  const { contrasena } = req.body;

  if (!email || !contrasena || typeof contrasena !== "string") {
    return res.status(400).json({ error: "Correo y contraseña son obligatorios." });
  }

  try {
    const result = await pool.query(`SELECT * FROM usuarios WHERE LOWER(email) = $1`, [email]);

    // Mensaje único: no revela si el correo existe o no (evita enumeración de usuarios)
    const MENSAJE_CREDENCIALES = "Correo o contraseña incorrectos.";

    if (result.rows.length === 0) {
      return res.status(401).json({ error: MENSAJE_CREDENCIALES });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(contrasena, user.contrasena_hash);
    if (!isMatch) {
      return res.status(401).json({ error: MENSAJE_CREDENCIALES });
    }

    if (user.activo === false) {
      return res.status(403).json({ error: "Tu cuenta está desactivada. Contacta al administrador." });
    }

    const token = jwt.sign(
      { id: user.usuario_id, rol: user.rol_id },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Inicio de sesión exitoso.",
      token,
      nombre_completo: user.nombre_completo,
      rol: user.rol_id,
      usuario: {
        id: user.usuario_id,
        nombre: user.nombre_completo,
        email: user.email,
        rol_id: user.rol_id
      }
    });

  } catch (error) {
    console.error("🔴 Error en login:", error);
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
