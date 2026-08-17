// src/routes/asignaturasRoutes.js
const express = require("express");
const router = express.Router();
const asignaturasController = require("../controllers/asignaturasControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

router.use(verifyToken);

// Cualquier usuario autenticado puede ver el listado (se usa en filtros/formularios)
router.get("/", authorizeRoles(1, 2, 3), asignaturasController.obtenerAsignaturas);

// Solo Admin/Docente puede crear asignaturas nuevas
router.post("/", authorizeRoles(1, 2), asignaturasController.crearAsignatura);

module.exports = router;
