const express = require('express');
const router = express.Router();
const usuariosController = require('../controllers/usuariosControllers');
const { verifyToken, authorizeRoles } = require('../middleware/authMiddleware');

const soloAdmin = authorizeRoles(1);

router.use(verifyToken);

// CRUD Usuarios
// GET /api/usuarios
router.get('/', soloAdmin, usuariosController.obtenerUsuarios); 

// POST /api/usuarios
router.post('/', soloAdmin, usuariosController.crearUsuario); 

// GET /api/usuarios/:id  <-- Fíjate: solo barra e ID
router.get('/:id', soloAdmin, usuariosController.obtenerUsuarioPorId); 

// PUT /api/usuarios/:id
router.put('/:id', soloAdmin, usuariosController.actualizarUsuario); 

// DELETE /api/usuarios/:id
router.delete('/:id', soloAdmin, usuariosController.desactivarUsuario);
module.exports = router;



// RUTA BASE: /api/usuarios (definida en app.js)



