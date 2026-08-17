// src/routes/horariosRoutes.js
const express = require("express");
const router = express.Router();
const horariosController = require("../controllers/horariosControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const adminODocente = authorizeRoles(1, 2);
const soloEstudiante = authorizeRoles(3);

router.use(verifyToken);

// 🎓 Estudiante: su propio horario real, según su titulación
router.get("/mi-horario", soloEstudiante, horariosController.obtenerMiHorario);

// 👩‍🏫 Admin/Docente: gestión de bloques de horario
router.post("/", adminODocente, horariosController.crearHorario);
router.get("/", adminODocente, horariosController.obtenerHorarios);
router.delete("/:id", adminODocente, horariosController.eliminarHorario);

module.exports = router;
