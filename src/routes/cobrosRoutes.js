// src/routes/cobrosRoutes.js
const express  = require("express");
const router   = express.Router();
const { validarIdParam } = require("../utils/validaciones");
// ":id" de obligaciones/planes/cuotas es numérico; en /estudiantes/:id es la cédula (10 dígitos), por eso
// no se usa router.param y el validador se aplica solo a las rutas con id numérico.
const idNum = (req, res, next) => validarIdParam(req, res, next, req.params.id);
const multer   = require("multer");
const c        = require("../controllers/cobrosControllers");
const p        = require("../controllers/cobrosPlanesControllers");
const n        = require("../controllers/cobrosNotificacionesControllers");
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
router.post("/obligaciones/:id/comprobante",         soloEstudiante, idNum, uploadComprobante.single("comprobante"), c.subirComprobante);

// ── Admin ──────────────────────────────────────────────────
router.get("/resumen",                          soloAdmin, c.obtenerResumenFinanciero);
router.get("/obligaciones",                     soloAdmin, c.obtenerObligaciones);
router.post("/obligaciones",                    soloAdmin, c.crearObligacion);
router.post("/obligaciones/importar-excel",     soloAdmin, upload.single("archivo"), c.importarObligacionesExcel);
router.get("/obligaciones/:id/pagos",            soloAdmin, idNum, c.obtenerPagosObligacion);
router.put("/pagar",                            soloAdmin, c.registrarPago);
router.put("/obligaciones/:id/comprobante/aprobar",  soloAdmin, idNum, c.aprobarComprobante);
router.put("/obligaciones/:id/comprobante/rechazar", soloAdmin, idNum, c.rechazarComprobante);

// ── Admin: planes de pago, cuotas, estado de cuenta y recargos ──
router.post("/planes",                          soloAdmin, p.crearPlan);
router.delete("/planes/:id",                    soloAdmin, idNum, p.eliminarPlan);
router.get("/estudiantes/:id/estado-cuenta",    soloAdmin, p.obtenerEstadoCuenta);
router.put("/estudiantes/:id/pagar",            soloAdmin, p.registrarPagoAcumulado);
router.put("/cuotas/:id/condonar-recargo",      soloAdmin, idNum, p.condonarRecargo);
router.put("/cuotas/:id",                       soloAdmin, idNum, p.editarCuota);
router.get("/configuracion",                    soloAdmin, p.obtenerConfiguracion);
router.put("/configuracion",                    soloAdmin, p.actualizarConfiguracion);
router.post("/recargos/aplicar",                soloAdmin, p.ejecutarRecargos);

// ── Admin: notificaciones por correo ──
router.post("/notificaciones/recordatorio",         soloAdmin, n.enviarRecordatorio);
router.post("/notificaciones/recordatorio-masivo",  soloAdmin, n.enviarRecordatorioMasivo);
router.get("/notificaciones",                       soloAdmin, n.listarNotificaciones);

module.exports = router;
