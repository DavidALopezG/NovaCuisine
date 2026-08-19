// src/routes/horariosRoutes.js
const express = require("express");
const router  = express.Router();
const c = require("../controllers/horariosControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const adminODocente  = authorizeRoles(1, 2);
const soloEstudiante = authorizeRoles(3);
const soloDocente    = authorizeRoles(2);

router.use(verifyToken);

// Rutas estáticas primero
router.get("/mi-horario",   soloEstudiante, c.obtenerMiHorario);
router.get("/mis-grupos",   soloDocente,    c.obtenerMisGrupos);

// Estudiantes de un grupo (docente ve quiénes asisten a su asignatura)
router.get("/mis-grupos/:asignatura_id/estudiantes", soloDocente, c.obtenerEstudiantesDeGrupo);

// Admin/Docente
router.get("/",    adminODocente, c.obtenerHorarios);
router.post("/",   adminODocente, c.crearHorario);
router.delete("/:id", adminODocente, c.eliminarHorario);

module.exports = router;
