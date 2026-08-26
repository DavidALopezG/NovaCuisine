// src/middleware/uploadArchivos.js
// Configuración compartida de multer con almacenamiento en disco, para
// archivos que el frontend necesita poder mostrar después (fotos de
// estudiante, comprobantes de pago). Se guardan bajo /uploads/<carpeta>/
// y se sirven como estáticos desde app.js.
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const BASE_UPLOADS_DIR = path.join(__dirname, "..", "..", "uploads");

function crearStorage(subcarpeta) {
    const destino = path.join(BASE_UPLOADS_DIR, subcarpeta);
    if (!fs.existsSync(destino)) {
        fs.mkdirSync(destino, { recursive: true });
    }
    return multer.diskStorage({
        destination: (req, file, cb) => cb(null, destino),
        filename: (req, file, cb) => {
            const ext = path.extname(file.originalname).toLowerCase();
            const nombreUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
            cb(null, nombreUnico);
        }
    });
}

const FILTRO_IMAGEN = (req, file, cb) => {
    const tiposPermitidos = ["image/jpeg", "image/png", "image/jpg", "image/webp"];
    if (!tiposPermitidos.includes(file.mimetype)) {
        return cb(new Error("Solo se permiten imágenes (jpg, jpeg, png, webp)."));
    }
    cb(null, true);
};

const FILTRO_COMPROBANTE = (req, file, cb) => {
    const tiposPermitidos = ["image/jpeg", "image/png", "image/jpg", "image/webp", "application/pdf"];
    if (!tiposPermitidos.includes(file.mimetype)) {
        return cb(new Error("Solo se permiten imágenes o PDF para el comprobante."));
    }
    cb(null, true);
};

// Foto tipo carnet del estudiante
const uploadFotoEstudiante = multer({
    storage: crearStorage("estudiantes"),
    limits: { fileSize: 3 * 1024 * 1024 }, // 3 MB
    fileFilter: FILTRO_IMAGEN
});

// Comprobante de pago (transferencia, Deuna, etc.)
const uploadComprobante = multer({
    storage: crearStorage("comprobantes"),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
    fileFilter: FILTRO_COMPROBANTE
});

module.exports = { uploadFotoEstudiante, uploadComprobante, BASE_UPLOADS_DIR };
