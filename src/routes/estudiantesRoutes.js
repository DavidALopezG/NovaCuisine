const express = require('express');
const router = express.Router();
const estudiantesController = require('../controllers/estudianteControllers');
const { verifyToken, authorizeRoles } = require('../middleware/authMiddleware');

const soloAdmin = authorizeRoles(1);

router.use(verifyToken);

// CRUD Estudiantes
router.post('/', soloAdmin, estudiantesController.crearEstudiante);
router.get('/', soloAdmin, estudiantesController.obtenerEstudiantes);
router.get('/:id', soloAdmin, estudiantesController.obtenerEstudiantePorId);
router.put('/:id', soloAdmin, estudiantesController.actualizarEstudiante);
router.delete('/:id', soloAdmin, estudiantesController.eliminarEstudiante);

module.exports = router;
