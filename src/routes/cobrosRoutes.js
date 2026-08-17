// backend/routes/cobrosRoutes.js (ACTUALIZADO)
const express = require('express');
const router = express.Router();
const multer = require('multer');
const cobrosController = require('../controllers/cobrosControllers');
const { verifyToken, authorizeRoles } = require('../middleware/authMiddleware');

const soloAdmin = authorizeRoles(1);
const soloEstudiante = authorizeRoles(3);
const upload = multer({ storage: multer.memoryStorage() }); // procesa el archivo en memoria, sin guardarlo en disco

router.use(verifyToken); 

// 🎓 Estudiante: ver su propio estado de cuenta
router.get('/mis-obligaciones', soloEstudiante, cobrosController.obtenerMisObligaciones);

// POST: Crear una nueva obligación
router.post('/obligaciones', soloAdmin, cobrosController.crearObligacion); //  Nueva ruta

// POST: Importar obligaciones masivamente desde un archivo Excel
router.post('/obligaciones/importar-excel', soloAdmin, upload.single('archivo'), cobrosController.importarObligacionesExcel);

// GET: Obtener todas las obligaciones (usamos esta para la gestión)
router.get('/obligaciones', soloAdmin, cobrosController.obtenerObligaciones); //  Nueva ruta

// PUT: Registrar un pago a una obligación existente (función crítica)
router.put('/pagar', soloAdmin, cobrosController.registrarPago); //  Nueva ruta

module.exports = router;