const jwt = require("jsonwebtoken");
require("dotenv").config();
const { requireEnv } = require("../config/env");
const pool = require("../db");
const JWT_SECRET = requireEnv("JWT_SECRET"); // antes tenía un valor hardcodeado aquí

async function verifyToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido." });

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado." });
  }

  // El token vale 2 h: se revalida contra la BD para que un usuario desactivado
  // (o con el rol cambiado) pierda acceso de inmediato, no al expirar el token.
  try {
    const r = await pool.query(
      `SELECT rol_id, activo FROM public.usuarios WHERE usuario_id = $1`,
      [decoded.id]
    );
    if (r.rows.length === 0 || r.rows[0].activo === false) {
      return res.status(401).json({ error: "Tu cuenta está desactivada o ya no existe." });
    }
    req.user = { ...decoded, rol: Number(r.rows[0].rol_id) };
    next();
  } catch (err) {
    console.error("🔴 verifyToken:", err);
    return res.status(500).json({ error: "Error al validar la sesión." });
  }
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.rol)) {
      return res.status(403).json({ error: "No tienes permiso para esta acción." });
    }
    next();
  };
}

module.exports = { verifyToken, authorizeRoles };
