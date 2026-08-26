// src/controllers/cobrosControllers.js
const pool = require("../db");
const XLSX = require("xlsx");

// Fecha de vencimiento por defecto: 3 meses a partir de hoy
const calcularFechaVencimiento = () => {
    const d = new Date();
    d.setMonth(d.getMonth() + 3);
    return d;
};

/* ═══════════════════════════════════════════════════════════
   1. POST /api/cobros/obligaciones  (Admin)
   ═══════════════════════════════════════════════════════════ */
async function crearObligacion(req, res) {
    const { estudiante_id, monto_total, fecha_vencimiento } = req.body;

    if (!estudiante_id || !monto_total) {
        return res.status(400).json({ error: "estudiante_id y monto_total son obligatorios." });
    }

    if (isNaN(monto_total) || Number(monto_total) <= 0) {
        return res.status(400).json({ error: "monto_total debe ser un número mayor a 0." });
    }

    try {
        const fecha = fecha_vencimiento
            ? new Date(fecha_vencimiento)
            : calcularFechaVencimiento();

        const result = await pool.query(
            `INSERT INTO public.cobros_obligaciones
                (estudiante_id, fecha_vencimiento, monto_total, monto_pagado, estado)
             VALUES ($1, $2, $3, 0.00, 'PENDIENTE') RETURNING *`,
            [estudiante_id, fecha, monto_total]
        );
        res.status(201).json({
            message: "Obligación creada correctamente.",
            obligacion: result.rows[0]
        });
    } catch (error) {
        console.error("🔴 crearObligacion:", error);
        res.status(500).json({ error: "Error interno al crear la obligación." });
    }
}

/* ═══════════════════════════════════════════════════════════
   2. GET /api/cobros/obligaciones  (Admin)
   ═══════════════════════════════════════════════════════════ */
async function obtenerObligaciones(req, res) {
    try {
        const result = await pool.query(
            `SELECT co.*, e.nombre, e.apellido, e.codigo_estudiante
             FROM public.cobros_obligaciones co
             LEFT JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
             ORDER BY
                CASE WHEN co.comprobante_estado = 'PENDIENTE' THEN 0 ELSE 1 END,
                co.fecha_vencimiento ASC`
        );
        res.json(result.rows);
    } catch (error) {
        console.error("🔴 obtenerObligaciones:", error);
        res.status(500).json({ error: "Error al obtener obligaciones." });
    }
}

/* ═══════════════════════════════════════════════════════════
   3. PUT /api/cobros/pagar  (Admin)
   FIX: usa client dedicado para que BEGIN/COMMIT sean en la
   misma conexión y no en conexiones aleatorias del pool.
   ═══════════════════════════════════════════════════════════ */
async function registrarPago(req, res) {
    const { obligacion_id, monto_pago } = req.body;

    if (!obligacion_id || !monto_pago || isNaN(Number(monto_pago)) || Number(monto_pago) <= 0) {
        return res.status(400).json({ error: "obligacion_id y monto_pago (mayor a 0) son obligatorios." });
    }

    const client = await pool.connect(); // ← cliente dedicado (FIX)
    try {
        const resultado = await aplicarPago(client, obligacion_id, monto_pago);
        res.json({
            message: "Pago registrado correctamente.",
            obligacion: resultado
        });
    } catch (error) {
        if (error.httpStatus) {
            return res.status(error.httpStatus).json({ error: error.message });
        }
        console.error("🔴 registrarPago:", error);
        res.status(500).json({ error: "Error interno al registrar el pago." });
    } finally {
        client.release(); // ← siempre liberar el cliente
    }
}

/**
 * Aplica un pago sobre una obligación dentro de su propia transacción.
 * Reutilizado tanto por registrarPago (pago manual del admin) como por
 * aprobarComprobante (pago derivado de un comprobante subido por el
 * estudiante y aprobado por el admin).
 */
async function aplicarPago(client, obligacion_id, monto_pago) {
    await client.query("BEGIN");
    try {
        const oblRes = await client.query(
            `SELECT monto_total, monto_pagado, estado
             FROM public.cobros_obligaciones
             WHERE obligacion_id = $1 FOR UPDATE`,
            [obligacion_id]
        );

        if (oblRes.rows.length === 0) {
            await client.query("ROLLBACK");
            throw Object.assign(new Error("Obligación no encontrada."), { httpStatus: 404 });
        }

        const obl = oblRes.rows[0];

        if (obl.estado === "PAGADO") {
            await client.query("ROLLBACK");
            throw Object.assign(new Error("Esta obligación ya está completamente pagada."), { httpStatus: 400 });
        }

        const nuevoMontoPagado = parseFloat(obl.monto_pagado) + parseFloat(monto_pago);
        const montoPendiente   = parseFloat(obl.monto_total) - nuevoMontoPagado;

        if (montoPendiente < -0.01) {
            await client.query("ROLLBACK");
            throw Object.assign(new Error("El monto del pago excede la deuda restante."), { httpStatus: 400 });
        }

        // FIX de estados: todos en MAYÚSCULAS para coincidir con VISTA_ESTADO_COBROS y CSS
        const nuevoEstado = montoPendiente <= 0 ? "PAGADO" : "PARCIAL";

        const updateRes = await client.query(
            `UPDATE public.cobros_obligaciones
             SET monto_pagado = $1,
                 estado = $2,
                 fecha_pago = NOW()
             WHERE obligacion_id = $3 RETURNING *`,
            [nuevoMontoPagado, nuevoEstado, obligacion_id]
        );

        await client.query("COMMIT");
        return updateRes.rows[0];
    } catch (error) {
        try { await client.query("ROLLBACK"); } catch (_) { /* ya en rollback */ }
        throw error;
    }
}

/* ═══════════════════════════════════════════════════════════
   4. POST /api/cobros/obligaciones/importar-excel  (Admin)
   ═══════════════════════════════════════════════════════════ */
async function importarObligacionesExcel(req, res) {
    if (!req.file) {
        return res.status(400).json({ error: "Debes adjuntar un archivo Excel (.xlsx o .xls)." });
    }

    let filas;
    try {
        const workbook = XLSX.read(req.file.buffer, { type: "buffer" });
        const hoja = workbook.SheetNames[0];
        filas = XLSX.utils.sheet_to_json(workbook.Sheets[hoja], { defval: null });
    } catch {
        return res.status(400).json({ error: "No se pudo leer el archivo. Verifica que sea un Excel válido." });
    }

    if (filas.length === 0) {
        return res.status(400).json({ error: "El archivo no contiene filas de datos." });
    }

    const insertadas = [];
    const errores    = [];
    const client     = await pool.connect();

    try {
        await client.query("BEGIN");

        for (let i = 0; i < filas.length; i++) {
            const fila       = filas[i];
            const numeroFila = i + 2;

            const claves = Object.keys(fila).reduce((acc, key) => {
                acc[key.toString().trim().toLowerCase().replace(/ /g, "_")] = fila[key];
                return acc;
            }, {});

            const estudiante_id       = claves["estudiante_id"];
            const monto_total         = claves["monto_total"];
            const fecha_vencimiento_r = claves["fecha_vencimiento"];

            if (!estudiante_id || monto_total === null || isNaN(Number(monto_total))) {
                errores.push({ fila: numeroFila, motivo: "estudiante_id o monto_total faltante/inválido." });
                continue;
            }

            const fecha = fecha_vencimiento_r
                ? new Date(fecha_vencimiento_r)
                : calcularFechaVencimiento();

            try {
                const r = await client.query(
                    `INSERT INTO public.cobros_obligaciones
                        (estudiante_id, fecha_vencimiento, monto_total, monto_pagado, estado)
                     VALUES ($1, $2, $3, 0.00, 'PENDIENTE') RETURNING *`,
                    [String(estudiante_id), fecha, Number(monto_total)]
                );
                insertadas.push(r.rows[0]);
            } catch (e) {
                errores.push({ fila: numeroFila, motivo: e.message });
            }
        }

        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        console.error("🔴 importarExcel:", error);
        return res.status(500).json({ error: "Error interno durante la importación." });
    } finally {
        client.release();
    }

    res.status(201).json({
        message: `Importación completada: ${insertadas.length} registradas, ${errores.length} con error.`,
        total_filas: filas.length,
        insertadas,
        errores
    });
}

/* ═══════════════════════════════════════════════════════════
   5. GET /api/cobros/mis-obligaciones  (Estudiante)
   ═══════════════════════════════════════════════════════════ */
async function obtenerMisObligaciones(req, res) {
    try {
        const result = await pool.query(
            `SELECT
                obligacion_id,
                fecha_vencimiento,
                monto_total,
                monto_pagado,
                (monto_total - monto_pagado) AS saldo_pendiente,
                estado,
                fecha_pago,
                comprobante_ruta,
                comprobante_monto_declarado,
                comprobante_estado,
                comprobante_fecha_subida,
                comprobante_observacion
             FROM public.cobros_obligaciones
             WHERE estudiante_id = $1
             ORDER BY fecha_vencimiento ASC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error("🔴 obtenerMisObligaciones:", error);
        res.status(500).json({ error: "Error al obtener tu estado de cuenta." });
    }
}

/* ═══════════════════════════════════════════════════════════
   5b. POST /api/cobros/obligaciones/:id/comprobante  (Estudiante)
   El estudiante sube su comprobante de transferencia/Deuna para
   una obligación propia. Queda en estado PENDIENTE hasta que el
   admin lo revise y apruebe (lo cual dispara aplicarPago) o lo
   rechace.
   ═══════════════════════════════════════════════════════════ */
async function subirComprobante(req, res) {
    const { id } = req.params;
    const { monto_declarado } = req.body;

    if (!req.file) {
        return res.status(400).json({ error: "Debes adjuntar el comprobante (imagen o PDF)." });
    }
    if (!monto_declarado || isNaN(Number(monto_declarado)) || Number(monto_declarado) <= 0) {
        return res.status(400).json({ error: "monto_declarado debe ser un número mayor a 0." });
    }

    try {
        // Solo puede subir comprobante de una obligación que le pertenece a él mismo
        const obligacion = await pool.query(
            `SELECT estudiante_id, estado FROM public.cobros_obligaciones WHERE obligacion_id = $1`,
            [id]
        );
        if (obligacion.rows.length === 0) {
            return res.status(404).json({ error: "Obligación no encontrada." });
        }
        if (Number(obligacion.rows[0].estudiante_id) !== Number(req.user.id)) {
            return res.status(403).json({ error: "No puedes subir un comprobante para una obligación que no es tuya." });
        }
        if (obligacion.rows[0].estado === "PAGADO") {
            return res.status(400).json({ error: "Esta obligación ya está completamente pagada." });
        }

        const rutaPublica = `/uploads/comprobantes/${req.file.filename}`;
        const result = await pool.query(
            `UPDATE public.cobros_obligaciones
             SET comprobante_ruta = $1,
                 comprobante_monto_declarado = $2,
                 comprobante_estado = 'PENDIENTE',
                 comprobante_fecha_subida = NOW(),
                 comprobante_observacion = NULL
             WHERE obligacion_id = $3
             RETURNING *`,
            [rutaPublica, monto_declarado, id]
        );

        res.status(201).json({
            message: "Comprobante subido. Un administrador lo revisará antes de aplicarlo como pago.",
            obligacion: result.rows[0]
        });
    } catch (error) {
        console.error("🔴 subirComprobante:", error);
        res.status(500).json({ error: "Error interno al subir el comprobante." });
    }
}

/* ═══════════════════════════════════════════════════════════
   5c. PUT /api/cobros/obligaciones/:id/comprobante/aprobar  (Admin)
   Aplica el monto declarado del comprobante como pago real
   (reutiliza la misma lógica transaccional que registrarPago).
   ═══════════════════════════════════════════════════════════ */
async function aprobarComprobante(req, res) {
    const { id } = req.params;

    const client = await pool.connect();
    try {
        const obligacion = await pool.query(
            `SELECT comprobante_estado, comprobante_monto_declarado
             FROM public.cobros_obligaciones WHERE obligacion_id = $1`,
            [id]
        );
        if (obligacion.rows.length === 0) {
            return res.status(404).json({ error: "Obligación no encontrada." });
        }
        if (obligacion.rows[0].comprobante_estado !== "PENDIENTE") {
            return res.status(400).json({ error: "Esta obligación no tiene un comprobante pendiente de revisión." });
        }

        const montoAplicar = obligacion.rows[0].comprobante_monto_declarado;
        const actualizada = await aplicarPago(client, id, montoAplicar);

        const resultado = await pool.query(
            `UPDATE public.cobros_obligaciones
             SET comprobante_estado = 'APROBADO'
             WHERE obligacion_id = $1
             RETURNING *`,
            [id]
        );

        res.json({
            message: `Comprobante aprobado. Se aplicó un pago de $${montoAplicar}.`,
            obligacion: resultado.rows[0] || actualizada
        });
    } catch (error) {
        if (error.httpStatus) {
            return res.status(error.httpStatus).json({ error: error.message });
        }
        console.error("🔴 aprobarComprobante:", error);
        res.status(500).json({ error: "Error interno al aprobar el comprobante." });
    } finally {
        client.release();
    }
}

/* ═══════════════════════════════════════════════════════════
   5d. PUT /api/cobros/obligaciones/:id/comprobante/rechazar  (Admin)
   ═══════════════════════════════════════════════════════════ */
async function rechazarComprobante(req, res) {
    const { id } = req.params;
    const { observacion } = req.body;

    try {
        const result = await pool.query(
            `UPDATE public.cobros_obligaciones
             SET comprobante_estado = 'RECHAZADO',
                 comprobante_observacion = $1
             WHERE obligacion_id = $2 AND comprobante_estado = 'PENDIENTE'
             RETURNING *`,
            [observacion || "Comprobante rechazado por el administrador.", id]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Esta obligación no tiene un comprobante pendiente de revisión." });
        }

        res.json({ message: "Comprobante rechazado.", obligacion: result.rows[0] });
    } catch (error) {
        console.error("🔴 rechazarComprobante:", error);
        res.status(500).json({ error: "Error interno al rechazar el comprobante." });
    }
}

/* ═══════════════════════════════════════════════════════════
   6. GET /api/cobros/resumen  (Admin — para Reportes)
   ═══════════════════════════════════════════════════════════ */
async function obtenerResumenFinanciero(req, res) {
    try {
        const result = await pool.query(`
            SELECT
                COALESCE(SUM(monto_pagado), 0)::numeric(10,2)                        AS total_recaudado,
                COALESCE(SUM(monto_total - monto_pagado), 0)::numeric(10,2)           AS total_pendiente,
                COUNT(*) FILTER (WHERE estado IN ('PENDIENTE','PARCIAL'))::int         AS obligaciones_pendientes,
                COUNT(DISTINCT estudiante_id) FILTER (
                    WHERE estado IN ('PENDIENTE','PARCIAL')
                    AND   fecha_vencimiento < NOW()
                )::int                                                                 AS estudiantes_morosos,
                CASE
                    WHEN SUM(monto_total) > 0
                    THEN ROUND(SUM(monto_pagado) / SUM(monto_total) * 100, 1)
                    ELSE 0
                END                                                                    AS efectividad_cobro
            FROM public.cobros_obligaciones
        `);

        const pagos = await pool.query(`
            SELECT
                co.obligacion_id,
                co.fecha_pago,
                co.monto_pagado AS monto,
                e.nombre || ' ' || e.apellido AS estudiante,
                e.codigo_estudiante
            FROM public.cobros_obligaciones co
            JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
            WHERE co.fecha_pago IS NOT NULL
            ORDER BY co.fecha_pago DESC
            LIMIT 10
        `);

        res.json({
            resumen: result.rows[0],
            pagosRecientes: pagos.rows
        });
    } catch (error) {
        console.error("🔴 obtenerResumenFinanciero:", error);
        res.status(500).json({ error: "Error al obtener el resumen financiero." });
    }
}

module.exports = {
    crearObligacion,
    obtenerObligaciones,
    registrarPago,
    importarObligacionesExcel,
    obtenerMisObligaciones,
    obtenerResumenFinanciero,
    subirComprobante,
    aprobarComprobante,
    rechazarComprobante
};
