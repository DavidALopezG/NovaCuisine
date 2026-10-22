// src/routes/asignaturasRoutes.js
const express = require("express");
const router = express.Router();
const { validarIdParam } = require("../utils/validaciones");
router.param("id", validarIdParam);
const asignaturasController = require("../controllers/asignaturasControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const soloAdmin = authorizeRoles(1);

router.use(verifyToken);

// Cualquier usuario autenticado puede ver el listado (se usa en filtros/formularios)
router.get("/", authorizeRoles(1, 2, 3), asignaturasController.obtenerAsignaturas);

// El pensum es materia institucional: crear, editar y eliminar es exclusivo del Administrador
router.post("/", soloAdmin, asignaturasController.crearAsignatura);

// El pensum (nivel, electivas, renombrar) es materia sensible del plan de
// estudios: editar/eliminar queda reservado exclusivamente al Administrador,
// para no dejar que un docente reestructure el pensum institucional.
router.put("/:id", soloAdmin, asignaturasController.actualizarAsignatura);
router.delete("/:id", soloAdmin, asignaturasController.eliminarAsignatura);

module.exports = router;
