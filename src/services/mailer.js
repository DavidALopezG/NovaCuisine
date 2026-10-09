// src/services/mailer.js
// Envío de correo con nodemailer (gratuito; funciona con cualquier SMTP, p. ej. Gmail con
// "contraseña de aplicación"). Variables de entorno (.env):
//   SMTP_HOST, SMTP_PORT (587), SMTP_SECURE (true solo para 465), SMTP_USER, SMTP_PASS, MAIL_FROM
//   MAIL_MODE=simulado  → no envía nada, solo registra en la bitácora (útil para demostrar sin SMTP)
// Si falta SMTP_HOST el modo es "simulado" automáticamente.
let transporte = null;

function modo() {
    if ((process.env.MAIL_MODE || "").toLowerCase() === "simulado") return "simulado";
    return process.env.SMTP_HOST ? "smtp" : "simulado";
}

function obtenerTransporte() {
    if (transporte) return transporte;
    const nodemailer = require("nodemailer"); // carga perezosa: el servidor arranca aunque no esté instalado
    transporte = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || "587"),
        secure: String(process.env.SMTP_SECURE || "false") === "true",
        auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
        connectionTimeout: 10000,
        socketTimeout: 15000
    });
    return transporte;
}

/** Devuelve { estado: 'ENVIADO' | 'SIMULADO', detalle } o lanza Error si el envío falla. */
async function enviarCorreo({ para, asunto, html, texto }) {
    if (modo() === "simulado") {
        return { estado: "SIMULADO", detalle: "Modo simulado: no se envió ningún correo real." };
    }
    const info = await obtenerTransporte().sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to: para,
        subject: asunto,
        html,
        text: texto
    });
    return { estado: "ENVIADO", detalle: String(info.messageId || "").slice(0, 200) };
}

module.exports = { enviarCorreo, modo };
