const express = require('express');
const router = express.Router();
const estudiantesController = require('../controllers/estudianteControllers');
const { verifyToken, authorizeRoles } = require('../middleware/authMiddleware');

const soloAdmin = authorizeRoles(1);
const adminODocente = authorizeRoles(1, 2);
const soloEstudiante = authorizeRoles(3);

router.use(verifyToken);

// 🎓 Perfil del propio estudiante autenticado (debe ir antes de "/:id")
router.get('/perfil/me', soloEstudiante, estudiantesController.obtenerMiPerfil);

// CRUD Estudiantes
router.post('/', soloAdmin, estudiantesController.crearEstudiante);
router.get('/', adminODocente, estudiantesController.obtenerEstudiantes); // Docente necesita listar para asignar recetas
router.get('/:id/detalle', soloAdmin, estudiantesController.obtenerDetalleEstudiante); // Expediente con recetas asignadas
router.get('/:id', soloAdmin, estudiantesController.obtenerEstudiantePorId);
router.put('/:id', soloAdmin, estudiantesController.actualizarEstudiante);
router.delete('/:id', soloAdmin, estudiantesController.eliminarEstudiante);

module.exports = router;
