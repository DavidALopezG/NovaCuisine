// src/routes/authRoutes.js
const express = require("express");
const router  = express.Router();
const { register, login } = require("../controllers/authcontrollers");
const { limitarIntentos } = require("../middleware/limitarIntentos");

// Máx. 10 intentos / 15 min por IP + correo (frena fuerza bruta sobre el login)
const limiteLogin = limitarIntentos({
    maxIntentos: 10,
    clave: (req) => `${req.ip}|${String(req.body?.email || "").toLowerCase()}`
});
// Máx. 5 registros / 15 min por IP (frena creación masiva de cuentas)
const limiteRegistro = limitarIntentos({ maxIntentos: 5, clave: (req) => req.ip });

// Rutas públicas (sin token)
router.post("/register", limiteRegistro, register);
router.post("/login",    limiteLogin, login);

// ⚠️  GET /auth/usuarios fue eliminado: era una ruta pública sin autenticación
// que exponía todos los usuarios descifrados. Usa GET /api/usuarios (protegida)

module.exports = router;
