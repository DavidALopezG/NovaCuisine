// src/routes/cobrosRoutes.js
const express  = require("express");
const router   = express.Router();
const multer   = require("multer");
const c        = require("../controllers/cobrosControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const soloAdmin      = authorizeRoles(1);
const soloEstudiante = authorizeRoles(3);
const upload         = multer({ storage: multer.memoryStorage() });

router.use(verifyToken);

// ── Estudiante ─────────────────────────────────────────────
router.get("/mis-obligaciones", soloEstudiante, c.obtenerMisObligaciones);

// ── Admin ──────────────────────────────────────────────────
router.get("/resumen",                          soloAdmin, c.obtenerResumenFinanciero);
router.get("/obligaciones",                     soloAdmin, c.obtenerObligaciones);
router.post("/obligaciones",                    soloAdmin, c.crearObligacion);
router.post("/obligaciones/importar-excel",     soloAdmin, upload.single("archivo"), c.importarObligacionesExcel);
router.put("/pagar",                            soloAdmin, c.registrarPago);

module.exports = router;
