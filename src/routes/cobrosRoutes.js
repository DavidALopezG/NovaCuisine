// src/routes/cobrosRoutes.js
const express  = require("express");
const router   = express.Router();
const multer   = require("multer");
const c        = require("../controllers/cobrosControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");
const { uploadComprobante } = require("../middleware/uploadArchivos");

const soloAdmin      = authorizeRoles(1);
const soloEstudiante = authorizeRoles(3);
const upload         = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB — de sobra para un Excel de obligaciones
    fileFilter: (req, file, cb) => {
        const tiposPermitidos = [
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ];
        if (!tiposPermitidos.includes(file.mimetype)) {
            return cb(new Error("Solo se permiten archivos Excel (.xls, .xlsx)."));
        }
        cb(null, true);
    }
});

router.use(verifyToken);

// ── Estudiante ─────────────────────────────────────────────
router.get("/mis-obligaciones",                     soloEstudiante, c.obtenerMisObligaciones);
router.post("/obligaciones/:id/comprobante",         soloEstudiante, uploadComprobante.single("comprobante"), c.subirComprobante);

// ── Admin ──────────────────────────────────────────────────
router.get("/resumen",                          soloAdmin, c.obtenerResumenFinanciero);
router.get("/obligaciones",                     soloAdmin, c.obtenerObligaciones);
router.post("/obligaciones",                    soloAdmin, c.crearObligacion);
router.post("/obligaciones/importar-excel",     soloAdmin, upload.single("archivo"), c.importarObligacionesExcel);
router.put("/pagar",                            soloAdmin, c.registrarPago);
router.put("/obligaciones/:id/comprobante/aprobar",  soloAdmin, c.aprobarComprobante);
router.put("/obligaciones/:id/comprobante/rechazar", soloAdmin, c.rechazarComprobante);

module.exports = router;
