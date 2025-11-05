// backend/routes/cobrosRoutes.js (ACTUALIZADO)
const express = require('express');
const router = express.Router();
const cobrosController = require('../controllers/cobrosControllers');
const { verifyToken, authorizeRoles } = require('../middleware/authMiddleware');

const soloAdmin = authorizeRoles(1);

router.use(verifyToken); 

// POST: Crear una nueva obligación
router.post('/obligaciones', soloAdmin, cobrosController.crearObligacion); // 👈 Nueva ruta

// GET: Obtener todas las obligaciones (usamos esta para la gestión)
router.get('/obligaciones', soloAdmin, cobrosController.obtenerObligaciones); // 👈 Nueva ruta

// PUT: Registrar un pago a una obligación existente (función crítica)
router.put('/pagar', soloAdmin, cobrosController.registrarPago); // 👈 Nueva ruta

module.exports = router;