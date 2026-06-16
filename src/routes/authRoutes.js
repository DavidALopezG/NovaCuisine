const express = require("express");
const router = express.Router();
const { register, login, getUsuarios } = require("../controllers/authcontrollers");

// RUTAS
router.post("/register", register);       // crear usuario
router.post("/login", login);            // login
router.get("/usuarios", getUsuarios);    // obtener usuarios

module.exports = router;
