// src/controllers/cobrosNotificacionesControllers.js
// Recordatorios de pago por correo: individual (botón en la fila del estudiante) y masivo
// (todos los estudiantes con cuotas vencidas). Cada intento queda en cobros_notificaciones.
const pool = require("../db");
const { emailValido, normalizarEmail } = require("../utils/validaciones");
const { aplicarRecargos } = require("../utils/cobrosCore");
const { enviarCorreo, modo } = require("../services/mailer");

const HORAS_ENTRE_AVISOS = 24;
const DIAS_POR_VENCER = 7;
const MAX_MASIVO = 200;

const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const usd = (n) => `$${Number(n).toFixed(2)}`;
const fechaCorta = (d) => new Date(d).toISOString().slice(0, 10);

/** Carga lo que se le debe avisar a un estudiante (cuotas vencidas y próximas a vencer). */
async function cargarPendientes(client, estudianteId) {
    const est = await client.query(
        `SELECT estudiante_id, nombre, apellido, email FROM public.estudiantes WHERE estudiante_id = $1`,
        [estudianteId]
    );
    if (est.rows.length === 0) return null;
    const cuotas = await client.query(
        `SELECT co.obligacion_id, co.concepto, co.numero_cuota, co.fecha_vencimiento::date AS vence,
                co.monto_total - co.monto_pagado AS saldo, co.recargo_acumulado,
                (co.fecha_vencimiento::date < CURRENT_DATE) AS vencida,
                (CURRENT_DATE - co.fecha_vencimiento::date) AS dias_mora
           FROM public.cobros_obligaciones co
          WHERE co.estudiante_id::text = $1::text
            AND co.estado <> 'PAGADO'
            AND co.fecha_vencimiento::date <= CURRENT_DATE + $2::int
          ORDER BY co.fecha_vencimiento`,
        [String(estudianteId), DIAS_POR_VENCER]
    );
    return { estudiante: est.rows[0], cuotas: cuotas.rows };
}

function armarCorreo({ estudiante, cuotas }) {
    const vencidas = cuotas.filter((c) => c.vencida);
    const porVencer = cuotas.filter((c) => !c.vencida);
    const totalVencido = vencidas.reduce((a, c) => a + parseFloat(c.saldo), 0);
    const nombre = `${estudiante.nombre} ${estudiante.apellido}`.trim();
    const fila = (c) => `<tr><td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(c.concepto || "Cobro")}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #eee">${fechaCorta(c.vence)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:right">${usd(c.saldo)}</td></tr>`;
    const tabla = (lista) => `<table style="border-collapse:collapse;font-size:14px"><thead><tr style="background:#f5f5f5">
        <th style="padding:6px 10px;text-align:left">Concepto</th><th style="padding:6px 10px;text-align:left">Vence</th>
        <th style="padding:6px 10px;text-align:right">Saldo</th></tr></thead><tbody>${lista.map(fila).join("")}</tbody></table>`;

    const asunto = vencidas.length > 0
        ? `NovaCuisine: tienes ${vencidas.length} pago(s) vencido(s) por ${usd(totalVencido)}`
        : "NovaCuisine: recordatorio de pagos próximos";

    let html = `<div style="font-family:Arial,sans-serif;color:#222;max-width:560px"><p>Hola ${esc(nombre)},</p>`;
    if (vencidas.length > 0) {
        html += `<p>Registramos pagos <b>vencidos</b> en tu cuenta (incluye recargos por mora, si aplican):</p>${tabla(vencidas)}
                 <p><b>Total vencido: ${usd(totalVencido)}</b></p>`;
    }
    if (porVencer.length > 0) {
        html += `<p>Próximos a vencer en ${DIAS_POR_VENCER} días:</p>${tabla(porVencer)}`;
    }
    html += `<p>Puedes subir tu comprobante desde el sistema (sección Mis pagos) o acercarte a secretaría.
             Si ya pagaste, ignora este mensaje.</p><p>Instituto NovaCuisine</p></div>`;

    const texto = [`Hola ${nombre},`,
        ...vencidas.map((c) => `VENCIDO: ${c.concepto} (${fechaCorta(c.vence)}) saldo ${usd(c.saldo)}`),
        ...porVencer.map((c) => `Por vencer: ${c.concepto} (${fechaCorta(c.vence)}) saldo ${usd(c.saldo)}`),
        "Sube tu comprobante en el sistema o acércate a secretaría."].join("\n");
    return { asunto, html, texto, vencidas: vencidas.length, totalVencido };
}

async function bitacora(client, estudianteId, email, asunto, estado, detalle, usuario) {
    await client.query(
        `INSERT INTO public.cobros_notificaciones (estudiante_id, email, asunto, estado, detalle, enviado_por)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [estudianteId, email || null, String(asunto).slice(0, 200), estado, detalle ? String(detalle).slice(0, 300) : null, String(usuario)]
    );
}

/**
 * Notifica a UN estudiante. Devuelve { ok, tipo, mensaje, estado? } sin lanzar por casos normales.
 * tipo: ENVIADO | SIMULADO | SIN_PENDIENTES | SIN_EMAIL | RECIENTE | ERROR | NO_EXISTE
 */
async function notificarEstudiante(estudianteId, { forzar = false, usuario }) {
    await aplicarRecargos(pool, { estudianteId });
    const datos = await cargarPendientes(pool, estudianteId);
    if (!datos) return { ok: false, tipo: "NO_EXISTE", mensaje: "El estudiante no existe." };
    const { estudiante, cuotas } = datos;
    if (cuotas.length === 0) return { ok: false, tipo: "SIN_PENDIENTES", mensaje: "No tiene cuotas vencidas ni próximas a vencer." };

    const email = normalizarEmail(estudiante.email);
    if (!emailValido(email)) {
        return { ok: false, tipo: "SIN_EMAIL", mensaje: "El estudiante no tiene un correo válido registrado." };
    }

    if (!forzar) {
        const rec = await pool.query(
            `SELECT enviado_en FROM public.cobros_notificaciones
              WHERE estudiante_id::text = $1::text AND estado IN ('ENVIADO','SIMULADO')
                AND enviado_en > NOW() - ($2::int * INTERVAL '1 hour')
              ORDER BY enviado_en DESC LIMIT 1`,
            [String(estudianteId), HORAS_ENTRE_AVISOS]
        );
        if (rec.rows.length > 0) {
            return { ok: false, tipo: "RECIENTE", mensaje: `Ya se le notificó en las últimas ${HORAS_ENTRE_AVISOS} horas.` };
        }
    }

    const correo = armarCorreo(datos);
    try {
        const r = await enviarCorreo({ para: email, asunto: correo.asunto, html: correo.html, texto: correo.texto });
        await bitacora(pool, estudianteId, email, correo.asunto, r.estado, r.detalle, usuario);
        return { ok: true, tipo: r.estado, mensaje: r.estado === "SIMULADO" ? "Correo simulado (SMTP no configurado)." : "Correo enviado.", email };
    } catch (error) {
        console.error("🔴 enviarCorreo:", error.message);
        await bitacora(pool, estudianteId, email, correo.asunto, "ERROR", error.message, usuario).catch(() => {});
        return { ok: false, tipo: "ERROR", mensaje: "No se pudo enviar el correo (revisa la configuración SMTP)." };
    }
}

// POST /api/cobros/notificaciones/recordatorio   { estudiante_id, forzar? }
async function enviarRecordatorio(req, res) {
    const { estudiante_id, forzar } = req.body || {};
    if (!estudiante_id) return res.status(400).json({ error: "estudiante_id es obligatorio." });
    try {
        const r = await notificarEstudiante(estudiante_id, { forzar: forzar === true, usuario: req.user.id });
        const http = r.ok ? 200 : r.tipo === "NO_EXISTE" ? 404 : r.tipo === "ERROR" ? 502 : r.tipo === "RECIENTE" ? 409 : 400;
        res.status(http).json({ ...(r.ok ? { message: r.mensaje } : { error: r.mensaje }), ...r, modo: modo() });
    } catch (error) {
        console.error("🔴 enviarRecordatorio:", error);
        res.status(500).json({ error: "Error interno del servidor." });
    }
}

// POST /api/cobros/notificaciones/recordatorio-masivo   { forzar? }  → todos los que tienen cuotas VENCIDAS
async function enviarRecordatorioMasivo(req, res) {
    try {
        await aplicarRecargos(pool);
        const r = await pool.query(
            `SELECT DISTINCT estudiante_id FROM public.cobros_obligaciones
              WHERE estado <> 'PAGADO' AND fecha_vencimiento::date < CURRENT_DATE
              LIMIT $1`, [MAX_MASIVO + 1]
        );
        if (r.rows.length > MAX_MASIVO) {
            return res.status(400).json({ error: `Hay más de ${MAX_MASIVO} estudiantes con mora; filtra o envía por tandas.` });
        }
        const resumen = { enviados: 0, simulados: 0, omitidos_recientes: 0, sin_email: 0, errores: 0, total: r.rows.length };
        for (const row of r.rows) {
            const x = await notificarEstudiante(row.estudiante_id, { forzar: req.body?.forzar === true, usuario: req.user.id });
            if (x.tipo === "ENVIADO") resumen.enviados++;
            else if (x.tipo === "SIMULADO") resumen.simulados++;
            else if (x.tipo === "RECIENTE") resumen.omitidos_recientes++;
            else if (x.tipo === "SIN_EMAIL") resumen.sin_email++;
            else if (x.tipo === "ERROR") resumen.errores++;
        }
        res.json({ message: "Proceso terminado.", modo: modo(), ...resumen });
    } catch (error) {
        console.error("🔴 enviarRecordatorioMasivo:", error);
        res.status(500).json({ error: "Error interno del servidor." });
    }
}

// GET /api/cobros/notificaciones?estudiante_id=
async function listarNotificaciones(req, res) {
    try {
        const est = req.query.estudiante_id ? String(req.query.estudiante_id) : null;
        const r = await pool.query(
            `SELECT n.*, e.nombre, e.apellido FROM public.cobros_notificaciones n
               LEFT JOIN public.estudiantes e ON e.estudiante_id::text = n.estudiante_id::text
              WHERE ($1::text IS NULL OR n.estudiante_id::text = $1::text)
              ORDER BY n.enviado_en DESC LIMIT 100`, [est]
        );
        res.json({ modo: modo(), notificaciones: r.rows });
    } catch (error) {
        console.error("🔴 listarNotificaciones:", error);
        res.status(500).json({ error: "Error interno del servidor." });
    }
}

module.exports = { enviarRecordatorio, enviarRecordatorioMasivo, listarNotificaciones, armarCorreo };
