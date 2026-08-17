// src/routes/insumosRoutes.js
const express = require("express");
const router = express.Router();
const insumosController = require("../controllers/insumosControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const adminODocente = authorizeRoles(1, 2);

router.use(verifyToken);

router.get("/", adminODocente, insumosController.obtenerInsumos);
router.post("/", adminODocente, insumosController.crearInsumo);

module.exports = router;
