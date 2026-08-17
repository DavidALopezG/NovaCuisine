// src/routes/titulacionesRoutes.js
const express = require("express");
const router = express.Router();
const titulacionesController = require("../controllers/titulacionesControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const adminODocente = authorizeRoles(1, 2);
const soloAdmin = authorizeRoles(1);

router.use(verifyToken);

router.get("/", adminODocente, titulacionesController.obtenerTitulaciones);
router.post("/", soloAdmin, titulacionesController.crearTitulacion);
router.put("/:id", soloAdmin, titulacionesController.actualizarTitulacion);
router.delete("/:id", soloAdmin, titulacionesController.eliminarTitulacion);

module.exports = router;
