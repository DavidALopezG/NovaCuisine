// src/routes/recetasRoutes.js
const express = require("express");
const router = express.Router();
const recetasController = require("../controllers/recetasControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

// Admin (1) y Docente (2) gestionan el recetario maestro.
// Estudiante (3) solo puede ver el detalle de sus recetas asignadas.
const adminODocente = authorizeRoles(1, 2);

router.use(verifyToken);

// 🎓 Estudiante: recetas que se le han asignado
router.get("/mis-recetas", authorizeRoles(3), recetasController.misRecetas);

// 📋 Recetario maestro (Docente/Admin)
router.post("/", adminODocente, recetasController.crearReceta);
router.get("/", adminODocente, recetasController.obtenerRecetas);

// Detalle: Admin, Docente o Estudiante (este último solo si tiene acceso asignado,
// validado dentro del controller)
router.get("/:id", authorizeRoles(1, 2, 3), recetasController.obtenerRecetaPorId);

router.put("/:id", adminODocente, recetasController.actualizarReceta);
router.delete("/:id", adminODocente, recetasController.eliminarReceta);

// 🔁 Versionado de recetas
router.post("/:id/versiones", adminODocente, recetasController.crearVersion);
router.put("/versiones/:version_id/aprobar", adminODocente, recetasController.aprobarVersion);

// 🔗 Asignación de recetas a estudiantes
router.post("/:id/asignar", adminODocente, recetasController.asignarReceta);

module.exports = router;
