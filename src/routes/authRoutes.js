// src/routes/authRoutes.js
const express = require("express");
const router  = express.Router();
const { register, login } = require("../controllers/authcontrollers");

// Rutas públicas (sin token)
router.post("/register", register);
router.post("/login",    login);

// ⚠️  GET /auth/usuarios fue eliminado: era una ruta pública sin autenticación
// que exponía todos los usuarios descifrados. Usa GET /api/usuarios (protegida)

module.exports = router;
