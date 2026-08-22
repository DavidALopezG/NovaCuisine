// src/routes/reportesRoutes.js
const express = require("express");
const router = express.Router();
const r = require("../controllers/reportesControllers");
const { verifyToken, authorizeRoles } = require("../middleware/authMiddleware");

const soloAdmin = authorizeRoles(1);

router.use(verifyToken, soloAdmin);

router.get("/resumen", r.obtenerResumen);
router.get("/serie-mensual", r.obtenerSerieMensual);
router.get("/por-titulacion", r.obtenerPorTitulacion);
router.get("/por-estado", r.obtenerPorEstado);
router.get("/obligaciones", r.obtenerObligacionesFiltradas);
router.get("/exportar/excel", r.exportarExcel);
router.get("/exportar/pdf", r.exportarPdf);

module.exports = router;
