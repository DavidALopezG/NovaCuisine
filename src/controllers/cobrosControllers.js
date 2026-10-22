// src/controllers/cobrosControllers.js
const pool = require("../db");
const XLSX = require("xlsx");
const { aCentavos, enteroPositivo, fechaISOValida, hoyISO } = require("../utils/validaciones");
const { aplicarRecargos, aplicarRecargosSiToca, estadoRealSql } = require("../utils/cobrosCore");

// Tope razonable de una obligación individual (USD). Evita montos absurdos por error de digitación.
const MONTO_MAXIMO_OBLIGACION = 10000;
const MAX_FILAS_EXCEL = 500;

// Fecha de vencimiento por defecto: 3 meses a partir de hoy, como "YYYY-MM-DD" local.
const calcularFechaVencimiento = () => {
    const d = new Date();
    d.setMonth(d.getMonth() + 3);
    return fechaISOValida(d);
};

/**
 * Las fechas de vencimiento se manejan SIEMPRE como texto "YYYY-MM-DD" (hora local).
 * Antes se usaba new Date("2026-10-21"), que es medianoche UTC = 19:00 del día anterior en Ecuador:
 * el vencimiento se guardaba un día antes y "hoy" se rechazaba como "anterior a hoy".
 */
const parsearFecha = (valor) => (valor === null || valor === undefined || valor === "" ? null : fechaISOValida(valor));

/* ═══════════════════════════════════════════════════════════
   1. POST /api/cobros/obligaciones  (Admin)
   ═══════════════════════════════════════════════════════════ */
async function crearObligacion(req, res) {
    const { estudiante_id, monto_total, fecha_vencimiento } = req.body;
    const concepto = req.body.concepto ? String(req.body.concepto).trim().slice(0, 120) : null;

    if (!estudiante_id || monto_total === undefined || monto_total === null || monto_total === "") {
        return res.status(400).json({ error: "estudiante_id y monto_total son obligatorios." });
    }

    const centavos = aCentavos(monto_total, MONTO_MAXIMO_OBLIGACION);
    if (centavos === null) {
        return res.status(400).json({
            error: `monto_total debe ser mayor a 0, con máximo 2 decimales y no superar $${MONTO_MAXIMO_OBLIGACION}.`
        });
    }

    let fecha = calcularFechaVencimiento();
    if (fecha_vencimiento) {
        fecha = parsearFecha(fecha_vencimiento);
        if (!fecha) {
            return res.status(400).json({ error: "fecha_vencimiento no es una fecha válida." });
        }
        if (fecha < hoyISO()) {
            return res.status(400).json({ error: "La fecha de vencimiento no puede ser anterior a hoy." });
        }
    }

    try {
        const est = await pool.query(
            `SELECT 1 FROM public.estudiantes WHERE estudiante_id = $1`, [String(estudiante_id)]
        );
        if (est.rows.length === 0) {
            return res.status(404).json({ error: "El estudiante no existe." });
        }

        if (concepto) {
            const dup = await pool.query(
                `SELECT 1 FROM public.cobros_obligaciones
                 WHERE estudiante_id = $1 AND LOWER(concepto) = LOWER($2)`,
                [String(estudiante_id), concepto]
            );
            if (dup.rows.length > 0) {
                return res.status(409).json({ error: `El estudiante ya tiene una obligación con el concepto "${concepto}".` });
            }
        }

        const result = await pool.query(
            `INSERT INTO public.cobros_obligaciones
                (estudiante_id, fecha_vencimiento, monto_total, monto_base, monto_pagado, estado, concepto, tipo)
             VALUES ($1, $2, $3, $3, 0.00, 'PENDIENTE', $4, 'OTRO') RETURNING *`,
            [String(estudiante_id), fecha, centavos / 100, concepto]
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
        await aplicarRecargosSiToca(pool);

        const result = await pool.query(
            `SELECT co.*,
                    COALESCE(co.monto_base, co.monto_total - co.recargo_acumulado) AS monto_base,
                    (co.monto_total - co.monto_pagado) AS saldo_pendiente,
                    ${estadoRealSql("co")} AS estado_real,
                    e.nombre, e.apellido, e.codigo_estudiante,
                    p.nombre AS plan_nombre,
                    (SELECT COUNT(*)::int FROM public.cobros_obligaciones x WHERE x.plan_id = co.plan_id) AS plan_total_cuotas
             FROM public.cobros_obligaciones co
             LEFT JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
             LEFT JOIN public.cobros_planes p ON p.plan_id = co.plan_id
             ORDER BY
                CASE WHEN co.comprobante_estado = 'PENDIENTE' THEN 0 ELSE 1 END,
                co.fecha_vencimiento ASC, co.numero_cuota ASC NULLS LAST`
        );
        res.json(result.rows);
    } catch (error) {
        console.error("🔴 obtenerObligaciones:", error);
        res.status(500).json({ error: "Error al obtener obligaciones." });
    }
}

/* ═══════════════════════════════════════════════════════════
   3. PUT /api/cobros/pagar  (Admin)
   ═══════════════════════════════════════════════════════════ */
async function registrarPago(req, res) {
    const { obligacion_id, monto_pago, metodo_pago } = req.body;

    const centavos = aCentavos(monto_pago, MONTO_MAXIMO_OBLIGACION);
    if (!/^\d{1,9}$/.test(String(obligacion_id ?? ""))) {
        return res.status(400).json({ error: "obligacion_id es obligatorio y debe ser numérico." });
    }
    if (!enteroPositivo(obligacion_id)) {
        return res.status(400).json({ error: "obligacion_id inválido." });
    }
    if (centavos === null) {
        return res.status(400).json({
            error: `monto_pago debe ser mayor a 0, con máximo 2 decimales y no superar $${MONTO_MAXIMO_OBLIGACION}.`
        });
    }
    const metodosValidos = ["EFECTIVO", "TRANSFERENCIA", "DEUNA", "OTRO"];
    if (metodo_pago && !metodosValidos.includes(metodo_pago)) {
        return res.status(400).json({ error: `metodo_pago debe ser uno de: ${metodosValidos.join(", ")}.` });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        const resultado = await aplicarPago(client, obligacion_id, centavos, {
            usuario: req.user.id, origen: "MANUAL", metodo: metodo_pago || null
        });
        await client.query("COMMIT");
        res.json({ message: "Pago registrado correctamente.", obligacion: resultado });
    } catch (error) {
        try { await client.query("ROLLBACK"); } catch (_) { /* ya en rollback */ }
        if (error.httpStatus) {
            return res.status(error.httpStatus).json({ error: error.message });
        }
        console.error("🔴 registrarPago:", error);
        res.status(500).json({ error: "Error interno al registrar el pago." });
    } finally {
        client.release();
    }
}

/**
 * Aplica un pago (en CENTAVOS) sobre una obligación. NO abre ni cierra la transacción:
 * quien la llama es responsable de BEGIN/COMMIT/ROLLBACK, para que pagar y marcar el
 * comprobante como aprobado sean una sola operación atómica.
 */
async function aplicarPago(client, obligacion_id, montoCentavos, { usuario = null, origen = "MANUAL", metodo = null, lote = null, recargosAlDia = false } = {}) {
    // Defensa en profundidad: esta función también la usan la aprobación de comprobantes
    // y el pago acumulado, así que nunca debe aceptar un monto inválido, venga de donde venga.
    if (!Number.isInteger(montoCentavos) || montoCentavos <= 0) {
        throw Object.assign(new Error("El monto del pago debe ser mayor a 0."), { httpStatus: 400 });
    }

    // Antes de cobrar, se carga cualquier recargo pendiente de esta cuota para que el saldo sea el real.
    // (El pago acumulado ya lo hizo para todo el estudiante, por eso puede omitirse con recargosAlDia.)
    if (!recargosAlDia) {
        await aplicarRecargos(client, { obligacionId: obligacion_id });
    }

    const oblRes = await client.query(
        `SELECT monto_total, monto_pagado, estado
         FROM public.cobros_obligaciones
         WHERE obligacion_id = $1 FOR UPDATE`,
        [obligacion_id]
    );

    if (oblRes.rows.length === 0) {
        throw Object.assign(new Error("Obligación no encontrada."), { httpStatus: 404 });
    }

    const obl = oblRes.rows[0];

    if (obl.estado === "PAGADO") {
        throw Object.assign(new Error("Esta obligación ya está completamente pagada."), { httpStatus: 400 });
    }

    // Aritmética en centavos enteros: evita errores de coma flotante con dinero
    const totalC    = Math.round(parseFloat(obl.monto_total) * 100);
    const pagadoC   = Math.round(parseFloat(obl.monto_pagado) * 100);
    const saldoC    = totalC - pagadoC;

    if (saldoC <= 0) {
        throw Object.assign(new Error("Esta obligación no tiene saldo pendiente."), { httpStatus: 400 });
    }
    if (montoCentavos > saldoC) {
        throw Object.assign(
            new Error(`El monto ($${(montoCentavos / 100).toFixed(2)}) excede el saldo pendiente ($${(saldoC / 100).toFixed(2)}).`),
            { httpStatus: 400 }
        );
    }

    const nuevoPagadoC = pagadoC + montoCentavos;
    const nuevoEstado  = nuevoPagadoC === totalC ? "PAGADO" : "PARCIAL";

    const updateRes = await client.query(
        `UPDATE public.cobros_obligaciones
         SET monto_pagado = $1, estado = $2, fecha_pago = NOW()
         WHERE obligacion_id = $3 RETURNING *`,
        [nuevoPagadoC / 100, nuevoEstado, obligacion_id]
    );

    // Historial: un registro por cada abono
    await client.query(
        `INSERT INTO public.cobros_pagos (obligacion_id, monto, registrado_por, origen, metodo_pago, lote)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [obligacion_id, montoCentavos / 100, usuario === null ? null : String(usuario), origen, metodo, lote]
    );

    return updateRes.rows[0];
}

/* ═══════════════════════════════════════════════════════════
   3b. GET /api/cobros/obligaciones/:id/pagos  (Admin)
   Historial de abonos de una obligación
   ═══════════════════════════════════════════════════════════ */
async function obtenerPagosObligacion(req, res) {
    try {
        const result = await pool.query(
            `SELECT pago_id, monto, fecha_pago, origen, metodo_pago, registrado_por
             FROM public.cobros_pagos
             WHERE obligacion_id = $1
             ORDER BY fecha_pago DESC`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error("🔴 obtenerPagosObligacion:", error);
        res.status(500).json({ error: "Error al obtener el historial de pagos." });
    }
}

/* ═══════════════════════════════════════════════════════════
   4. POST /api/cobros/obligaciones/importar-excel  (Admin)
   Columnas: estudiante_id, monto_total, fecha_vencimiento (opcional), concepto (opcional)
   Cada fila va en su propio SAVEPOINT: una fila con error NO invalida las demás.
   ═══════════════════════════════════════════════════════════ */
async function importarObligacionesExcel(req, res) {
    if (!req.file) {
        return res.status(400).json({ error: "Debes adjuntar un archivo Excel (.xlsx o .xls)." });
    }

    let filas;
    try {
        // cellDates: las fechas de Excel llegan como Date (antes llegaban como número serial → año 1900)
        const workbook = XLSX.read(req.file.buffer, { type: "buffer", cellDates: true });
        const hoja = workbook.SheetNames[0];
        filas = XLSX.utils.sheet_to_json(workbook.Sheets[hoja], { defval: null });
    } catch {
        return res.status(400).json({ error: "No se pudo leer el archivo. Verifica que sea un Excel válido." });
    }

    if (filas.length === 0) {
        return res.status(400).json({ error: "El archivo no contiene filas de datos." });
    }
    if (filas.length > MAX_FILAS_EXCEL) {
        return res.status(400).json({ error: `El archivo supera el máximo de ${MAX_FILAS_EXCEL} filas por importación.` });
    }

    const insertadas = [];
    const errores    = [];
    const client     = await pool.connect();

    try {
        await client.query("BEGIN");
        const hoy = hoyISO();

        for (let i = 0; i < filas.length; i++) {
            const fila       = filas[i];
            const numeroFila = i + 2;

            const claves = Object.keys(fila).reduce((acc, key) => {
                acc[key.toString().trim().toLowerCase().replace(/ /g, "_")] = fila[key];
                return acc;
            }, {});

            const estudiante_id = claves["estudiante_id"] !== null && claves["estudiante_id"] !== undefined
                ? String(claves["estudiante_id"]).trim() : "";
            const concepto = claves["concepto"] ? String(claves["concepto"]).trim().slice(0, 120) : null;

            if (!estudiante_id) {
                errores.push({ fila: numeroFila, motivo: "estudiante_id faltante." });
                continue;
            }

            const centavos = aCentavos(claves["monto_total"], MONTO_MAXIMO_OBLIGACION);
            if (centavos === null) {
                errores.push({
                    fila: numeroFila,
                    motivo: `monto_total inválido (debe ser > 0, máx. 2 decimales y ≤ $${MONTO_MAXIMO_OBLIGACION}).`
                });
                continue;
            }

            let fecha = calcularFechaVencimiento();
            if (claves["fecha_vencimiento"]) {
                fecha = parsearFecha(claves["fecha_vencimiento"]);
                if (!fecha) {
                    errores.push({ fila: numeroFila, motivo: "fecha_vencimiento no es una fecha válida." });
                    continue;
                }
                if (fecha < hoy) {
                    errores.push({ fila: numeroFila, motivo: "fecha_vencimiento anterior a hoy." });
                    continue;
                }
            }

            await client.query("SAVEPOINT fila_import");
            try {
                const est = await client.query(
                    `SELECT 1 FROM public.estudiantes WHERE estudiante_id = $1`, [estudiante_id]
                );
                if (est.rows.length === 0) {
                    await client.query("ROLLBACK TO SAVEPOINT fila_import");
                    errores.push({ fila: numeroFila, motivo: `El estudiante ${estudiante_id} no existe.` });
                    continue;
                }

                if (concepto) {
                    const dup = await client.query(
                        `SELECT 1 FROM public.cobros_obligaciones
                         WHERE estudiante_id = $1 AND LOWER(concepto) = LOWER($2)`,
                        [estudiante_id, concepto]
                    );
                    if (dup.rows.length > 0) {
                        await client.query("ROLLBACK TO SAVEPOINT fila_import");
                        errores.push({ fila: numeroFila, motivo: `Ya existe una obligación "${concepto}" para ese estudiante.` });
                        continue;
                    }
                }

                const r = await client.query(
                    `INSERT INTO public.cobros_obligaciones
                        (estudiante_id, fecha_vencimiento, monto_total, monto_base, monto_pagado, estado, concepto, tipo)
                     VALUES ($1, $2, $3, $3, 0.00, 'PENDIENTE', $4, 'OTRO') RETURNING *`,
                    [estudiante_id, fecha, centavos / 100, concepto]
                );
                await client.query("RELEASE SAVEPOINT fila_import");
                insertadas.push(r.rows[0]);
            } catch (e) {
                await client.query("ROLLBACK TO SAVEPOINT fila_import");
                errores.push({ fila: numeroFila, motivo: "Error al guardar la fila." });
                console.error(`🔴 importarExcel fila ${numeroFila}:`, e.message);
            }
        }

        await client.query("COMMIT");
    } catch (error) {
        try { await client.query("ROLLBACK"); } catch (_) { /* noop */ }
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
        await aplicarRecargosSiToca(pool);
        const result = await pool.query(
            `SELECT
                obligacion_id,
                fecha_vencimiento,
                concepto,
                tipo,
                numero_cuota,
                plan_id,
                COALESCE(monto_base, monto_total - recargo_acumulado) AS monto_base,
                recargo_acumulado,
                monto_total,
                monto_pagado,
                (monto_total - monto_pagado) AS saldo_pendiente,
                estado,
                ${estadoRealSql("cobros_obligaciones")} AS estado_real,
                fecha_pago,
                comprobante_ruta,
                comprobante_monto_declarado,
                comprobante_estado,
                comprobante_fecha_subida,
                comprobante_observacion
             FROM public.cobros_obligaciones
             WHERE estudiante_id = $1
             ORDER BY fecha_vencimiento ASC, numero_cuota ASC NULLS LAST`,
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

    // multer ya guardó el archivo en disco antes de llegar aquí: si se rechaza la petición hay que borrarlo
    const descartarArchivo = () => { if (req.file) require("fs").unlink(req.file.path, () => {}); };

    if (!req.file) {
        return (descartarArchivo(), res.status(400)).json({ error: "Debes adjuntar el comprobante (imagen o PDF)." });
    }
    const declaradoC = aCentavos(monto_declarado, MONTO_MAXIMO_OBLIGACION);
    if (declaradoC === null) {
        return (descartarArchivo(), res.status(400)).json({ error: "monto_declarado debe ser mayor a 0 y tener máximo 2 decimales." });
    }

    try {
        // Solo puede subir comprobante de una obligación que le pertenece a él mismo
        const obligacion = await pool.query(
            `SELECT estudiante_id, estado, monto_total, monto_pagado, comprobante_estado
             FROM public.cobros_obligaciones WHERE obligacion_id = $1`,
            [id]
        );
        if (obligacion.rows.length === 0) {
            return (descartarArchivo(), res.status(404)).json({ error: "Obligación no encontrada." });
        }
        if (Number(obligacion.rows[0].estudiante_id) !== Number(req.user.id)) {
            return (descartarArchivo(), res.status(403)).json({ error: "No puedes subir un comprobante para una obligación que no es tuya." });
        }
        if (obligacion.rows[0].estado === "PAGADO") {
            return (descartarArchivo(), res.status(400)).json({ error: "Esta obligación ya está completamente pagada." });
        }
        // No sobrescribir un comprobante que el admin todavía no revisó (se perdería el anterior)
        if (obligacion.rows[0].comprobante_estado === "PENDIENTE") {
            return (descartarArchivo(), res.status(409)).json({ error: "Ya tienes un comprobante en revisión para esta obligación. Espera la respuesta del administrador." });
        }
        const saldoC = Math.round(parseFloat(obligacion.rows[0].monto_total) * 100)
                     - Math.round(parseFloat(obligacion.rows[0].monto_pagado) * 100);
        if (declaradoC > saldoC) {
            return (descartarArchivo(), res.status(400)).json({
                error: `El monto declarado ($${(declaradoC / 100).toFixed(2)}) supera tu saldo pendiente ($${(saldoC / 100).toFixed(2)}).`
            });
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
            [rutaPublica, declaradoC / 100, id]
        );

        res.status(201).json({
            message: "Comprobante subido. Un administrador lo revisará antes de aplicarlo como pago.",
            obligacion: result.rows[0]
        });
    } catch (error) {
        descartarArchivo();
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
        await client.query("BEGIN");

        // FOR UPDATE: dos admins aprobando a la vez no pueden aplicar el mismo comprobante dos veces
        const obligacion = await client.query(
            `SELECT comprobante_estado, comprobante_monto_declarado
             FROM public.cobros_obligaciones WHERE obligacion_id = $1 FOR UPDATE`,
            [id]
        );
        if (obligacion.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: "Obligación no encontrada." });
        }
        if (obligacion.rows[0].comprobante_estado !== "PENDIENTE") {
            await client.query("ROLLBACK");
            return res.status(400).json({ error: "Esta obligación no tiene un comprobante pendiente de revisión." });
        }

        const montoAplicar = Number(obligacion.rows[0].comprobante_monto_declarado);
        const centavos = aCentavos(montoAplicar, MONTO_MAXIMO_OBLIGACION);
        if (centavos === null) {
            await client.query("ROLLBACK");
            return res.status(400).json({ error: "El monto declarado del comprobante no es válido." });
        }

        await aplicarPago(client, id, centavos, {
            usuario: req.user.id, origen: "COMPROBANTE", metodo: "TRANSFERENCIA"
        });

        const resultado = await client.query(
            `UPDATE public.cobros_obligaciones
             SET comprobante_estado = 'APROBADO'
             WHERE obligacion_id = $1
             RETURNING *`,
            [id]
        );

        await client.query("COMMIT");

        res.json({
            message: `Comprobante aprobado. Se aplicó un pago de $${(centavos / 100).toFixed(2)}.`,
            obligacion: resultado.rows[0]
        });
    } catch (error) {
        try { await client.query("ROLLBACK"); } catch (_) { /* ya en rollback */ }
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
    const observacion = req.body.observacion ? String(req.body.observacion).trim().slice(0, 300) : null;

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
        await aplicarRecargosSiToca(pool);

        const result = await pool.query(`
            SELECT
                COALESCE(SUM(monto_pagado), 0)::numeric(10,2)                        AS total_recaudado,
                COALESCE(SUM(monto_total - monto_pagado), 0)::numeric(10,2)           AS total_pendiente,
                COUNT(*) FILTER (WHERE estado IN ('PENDIENTE','PARCIAL'))::int         AS obligaciones_pendientes,
                COUNT(DISTINCT estudiante_id) FILTER (
                    WHERE estado IN ('PENDIENTE','PARCIAL')
                    AND   fecha_vencimiento::date < CURRENT_DATE
                )::int                                                                 AS estudiantes_morosos,
                COALESCE(SUM(monto_total - monto_pagado) FILTER (
                    WHERE estado <> 'PAGADO' AND fecha_vencimiento::date < CURRENT_DATE
                ), 0)::numeric(10,2)                                                   AS total_vencido,
                COUNT(*) FILTER (
                    WHERE estado <> 'PAGADO' AND fecha_vencimiento::date < CURRENT_DATE
                )::int                                                                 AS cuotas_vencidas,
                COALESCE(SUM(recargo_acumulado), 0)::numeric(10,2)                     AS total_recargos,
                COALESCE(SUM(monto_total - monto_pagado) FILTER (
                    WHERE estado <> 'PAGADO'
                    AND fecha_vencimiento::date BETWEEN CURRENT_DATE AND CURRENT_DATE + 30
                ), 0)::numeric(10,2)                                                   AS por_vencer_30d,
                CASE
                    WHEN SUM(monto_total) > 0
                    THEN ROUND(SUM(monto_pagado) / SUM(monto_total) * 100, 1)
                    ELSE 0
                END                                                                    AS efectividad_cobro
            FROM public.cobros_obligaciones
        `);

        const pagos = await pool.query(`
            SELECT
                p.pago_id,
                p.obligacion_id,
                p.fecha_pago,
                p.monto,
                e.nombre || ' ' || e.apellido AS estudiante,
                e.codigo_estudiante
            FROM public.cobros_pagos p
            JOIN public.cobros_obligaciones co ON co.obligacion_id = p.obligacion_id
            JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
            ORDER BY p.fecha_pago DESC
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
    aplicarPago,
    obtenerPagosObligacion,
    importarObligacionesExcel,
    obtenerMisObligaciones,
    obtenerResumenFinanciero,
    subirComprobante,
    aprobarComprobante,
    rechazarComprobante
};
