// src/routes/recetasRoutes.js
const express = require("express");
const router = express.Router();
const c = require("../controllers/recetasControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const adminODocente = authorizeRoles(1, 2);
const todos = authorizeRoles(1, 2, 3);

router.use(verifyToken);

// ⚠️ RUTAS ESTÁTICAS PRIMERO — antes de cualquier /:id
// Si se declaran después de /:id, Express las interpreta como un ID
router.get("/mis-recetas", authorizeRoles(3), c.misRecetas);
router.put("/versiones/:version_id/aprobar", adminODocente, c.aprobarVersion);

// Recetario maestro (Docente/Admin)
router.post("/", adminODocente, c.crearReceta);
router.get("/", adminODocente, c.obtenerRecetas);

// Detalle: todos los roles (el controller valida acceso del estudiante internamente)
router.get("/:id", todos, c.obtenerRecetaPorId);
router.put("/:id", adminODocente, c.actualizarReceta);
router.delete("/:id", adminODocente, c.eliminarReceta);

// Versionado y asignación
router.post("/:id/versiones", adminODocente, c.crearVersion);
router.post("/:id/asignar", adminODocente, c.asignarReceta);

module.exports = router;
