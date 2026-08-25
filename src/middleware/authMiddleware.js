const jwt = require("jsonwebtoken");
require("dotenv").config();
const { requireEnv } = require("../config/env");
const JWT_SECRET = requireEnv("JWT_SECRET"); // antes tenía un valor hardcodeado aquí

function verifyToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "Token requerido." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado." });
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
