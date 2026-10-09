// src/controllers/cobrosPlanesControllers.js
// Planes de pago por cuotas mensuales, pago acumulado, estado de cuenta, edición de cuotas,
// condonación de recargos y configuración de la mora. Todas las rutas son de Administrador.
const crypto = require("crypto");
const pool = require("../db");
const { aCentavos } = require("../utils/validaciones");
const {
    aplicarRecargos,
    estadoRealSql,
    distribuirPago,
    aCentavosDesdeDb,
    registrarAjuste
} = require("../utils/cobrosCore");
const { aplicarPago } = require("./cobrosControllers");

const TIPOS_CUOTA = ["MATRICULA", "MENSUALIDAD", "OTRO"];
const METODOS_PAGO = ["EFECTIVO", "TRANSFERENCIA", "DEUNA", "OTRO"];
const MONTO_MAXIMO_CUOTA = 10000;
const MAX_CUOTAS_PLAN = 36;

const dinero = (centavos) => (centavos / 100).toFixed(2);

/** Valida 'YYYY-MM-DD' (fecha real, sin desfases de zona horaria) y un rango razonable. */
function parseFechaISO(valor) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(valor || ""));
    if (!m) return null;
    const [_, y, mo, d] = m;
    const fecha = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d)));
    if (fecha.getUTCFullYear() !== Number(y) || fecha.getUTCMonth() !== Number(mo) - 1 || fecha.getUTCDate() !== Number(d)) {
        return null; // p. ej. 2026-02-31
    }
    const anio = Number(y);
    const anioActual = new Date().getUTCFullYear();
    if (anio < anioActual - 3 || anio > anioActual + 5) return null;
    return `${y}-${mo}-${d}`;
}

// Error controlado que lleva el código HTTP
const falla = (httpStatus, mensaje, extra = {}) => Object.assign(new Error(mensaje), { httpStatus, extra });

function responderError(res, error, etiqueta) {
    if (error.httpStatus) {
        return res.status(error.httpStatus).json({ error: error.message, ...(error.extra || {}) });
    }
    console.error(`🔴 ${etiqueta}:`, error);
    return res.status(500).json({ error: "Error interno del servidor." });
}

async function conTransaccion(fn) {
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        const resultado = await fn(client);
        await client.query("COMMIT");
        return resultado;
    } catch (error) {
        try { await client.query("ROLLBACK"); } catch (_) { /* ya en rollback */ }
        throw error;
    } finally {
        client.release();
    }
}

/* ═══════════════════════════════════════════════════════════
   1. POST /api/cobros/planes
   Crea un plan con sus cuotas (el frontend las genera y el admin las ajusta).
   ═══════════════════════════════════════════════════════════ */
async function crearPlan(req, res) {
    try {
        const estudiante_id = String(req.body.estudiante_id || "").trim();
        const nombre = req.body.nombre ? String(req.body.nombre).trim().slice(0, 120) : null;
        const observacion = req.body.observacion ? String(req.body.observacion).trim().slice(0, 300) : null;
        const entrada = req.body.cuotas;

        if (!estudiante_id) {
            throw falla(400, "estudiante_id es obligatorio.");
        }
        if (!Array.isArray(entrada) || entrada.length === 0) {
            throw falla(400, "El plan debe tener al menos una cuota.");
        }
        if (entrada.length > MAX_CUOTAS_PLAN) {
            throw falla(400, `Un plan no puede tener más de ${MAX_CUOTAS_PLAN} cuotas.`);
        }

        const cuotas = [];
        const conceptosVistos = new Set();
        let matriculas = 0;
        entrada.forEach((c, i) => {
            const n = i + 1;
            const concepto = String(c?.concepto || "").trim();
            if (concepto.length < 3 || concepto.length > 120) {
                throw falla(400, `Cuota ${n}: el concepto debe tener entre 3 y 120 caracteres.`);
            }
            const clave = concepto.toLowerCase();
            if (conceptosVistos.has(clave)) {
                throw falla(400, `Cuota ${n}: el concepto "${concepto}" está repetido dentro del plan.`);
            }
            conceptosVistos.add(clave);

            const tipo = String(c?.tipo || "MENSUALIDAD").toUpperCase();
            if (!TIPOS_CUOTA.includes(tipo)) {
                throw falla(400, `Cuota ${n}: tipo debe ser ${TIPOS_CUOTA.join(", ")}.`);
            }
            if (tipo === "MATRICULA") matriculas++;

            const centavos = aCentavos(c?.monto, MONTO_MAXIMO_CUOTA);
            if (centavos === null) {
                throw falla(400, `Cuota ${n}: el monto debe ser mayor a 0, con máximo 2 decimales y no superar $${MONTO_MAXIMO_CUOTA}.`);
            }
            const fecha = parseFechaISO(c?.fecha_vencimiento);
            if (!fecha) {
                throw falla(400, `Cuota ${n}: la fecha de vencimiento no es válida.`);
            }
            cuotas.push({ concepto, tipo, centavos, fecha });
        });
        if (matriculas > 1) {
            throw falla(400, "Un plan solo puede tener una matrícula.");
        }

        // Orden definitivo: por fecha y, a igual fecha, la matrícula primero
        cuotas.sort((a, b) => a.fecha.localeCompare(b.fecha) || (a.tipo === "MATRICULA" ? -1 : 0) - (b.tipo === "MATRICULA" ? -1 : 0));

        const resultado = await conTransaccion(async (client) => {
            // Bloquea la fila del estudiante: dos planes simultáneos para la misma persona se serializan
            const est = await client.query(
                `SELECT nombre, apellido FROM public.estudiantes WHERE estudiante_id = $1 FOR UPDATE`,
                [estudiante_id]
            );
            if (est.rows.length === 0) throw falla(404, "El estudiante no existe.");

            const choque = await client.query(
                `SELECT concepto FROM public.cobros_obligaciones
                  WHERE estudiante_id = $1 AND LOWER(concepto) = ANY($2::text[])`,
                [estudiante_id, cuotas.map(c => c.concepto.toLowerCase())]
            );
            if (choque.rows.length > 0) {
                throw falla(409, `El estudiante ya tiene cuotas con estos conceptos: ${choque.rows.map(r => r.concepto).join(", ")}.`);
            }

            const nombrePlan = nombre || `Plan de pagos desde ${cuotas[0].fecha}`;
            const plan = await client.query(
                `INSERT INTO public.cobros_planes (estudiante_id, nombre, observacion, creado_por)
                 VALUES ($1, $2, $3, $4) RETURNING *`,
                [estudiante_id, nombrePlan, observacion, String(req.user.id)]
            );

            const creadas = [];
            for (let i = 0; i < cuotas.length; i++) {
                const c = cuotas[i];
                const r = await client.query(
                    `INSERT INTO public.cobros_obligaciones
                        (estudiante_id, fecha_vencimiento, monto_total, monto_base, monto_pagado, estado,
                         concepto, tipo, plan_id, numero_cuota)
                     VALUES ($1, $2, $3, $3, 0.00, 'PENDIENTE', $4, $5, $6, $7)
                     RETURNING *`,
                    [estudiante_id, c.fecha, c.centavos / 100, c.concepto, c.tipo, plan.rows[0].plan_id, i + 1]
                );
                creadas.push(r.rows[0]);
            }
            return { plan: plan.rows[0], cuotas: creadas };
        });

        res.status(201).json({ message: `Plan creado con ${resultado.cuotas.length} cuota(s).`, ...resultado });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ error: "Ya existe una cuota con ese número en el plan. Intenta de nuevo." });
        }
        responderError(res, error, "crearPlan");
    }
}

/* ═══════════════════════════════════════════════════════════
   2. GET /api/cobros/estudiantes/:id/estado-cuenta
   Cuotas mes a mes, pagos, recargos y resumen de un estudiante.
   ═══════════════════════════════════════════════════════════ */
async function obtenerEstadoCuenta(req, res) {
    try {
        const estudianteId = String(req.params.id);

        const est = await pool.query(
            `SELECT e.estudiante_id, e.nombre, e.apellido, e.email, e.codigo_estudiante, e.cedula,
                    e.titulacion_id, t.nombre_titulacion, t.duracion_meses
               FROM public.estudiantes e
               LEFT JOIN public.titulaciones t ON t.titulacion_id = e.titulacion_id
              WHERE e.estudiante_id = $1`,
            [estudianteId]
        );
        if (est.rows.length === 0) {
            return res.status(404).json({ error: "El estudiante no existe." });
        }

        // Deja los recargos al día antes de mostrar saldos
        await aplicarRecargos(pool, { estudianteId });

        const cuotasRes = await pool.query(
            `SELECT co.obligacion_id, co.plan_id, p.nombre AS plan_nombre, co.numero_cuota, co.tipo, co.concepto,
                    co.fecha_vencimiento,
                    to_char(co.fecha_vencimiento::date, 'YYYY-MM') AS mes,
                    COALESCE(co.monto_base, co.monto_total - co.recargo_acumulado) AS monto_base,
                    co.recargo_acumulado, co.recargo_meses_aplicados,
                    co.monto_total, co.monto_pagado,
                    (co.monto_total - co.monto_pagado) AS saldo,
                    co.estado, ${estadoRealSql("co")} AS estado_real, co.fecha_pago,
                    CASE WHEN co.estado <> 'PAGADO' AND co.fecha_vencimiento::date < CURRENT_DATE
                         THEN (CURRENT_DATE - co.fecha_vencimiento::date) ELSE 0 END AS dias_mora,
                    co.comprobante_estado, co.comprobante_monto_declarado, co.comprobante_ruta
               FROM public.cobros_obligaciones co
               LEFT JOIN public.cobros_planes p ON p.plan_id = co.plan_id
              WHERE co.estudiante_id = $1
              ORDER BY co.fecha_vencimiento ASC, co.numero_cuota ASC NULLS LAST, co.obligacion_id ASC`,
            [estudianteId]
        );

        const pagosRes = await pool.query(
            `SELECT pg.pago_id, pg.obligacion_id, co.concepto, pg.monto, pg.fecha_pago,
                    pg.origen, pg.metodo_pago, pg.registrado_por, pg.lote
               FROM public.cobros_pagos pg
               JOIN public.cobros_obligaciones co ON co.obligacion_id = pg.obligacion_id
              WHERE co.estudiante_id = $1
              ORDER BY pg.fecha_pago DESC, pg.pago_id DESC`,
            [estudianteId]
        );

        const ajustesRes = await pool.query(
            `SELECT a.ajuste_id, a.tipo, a.obligacion_id, a.monto, a.detalle, a.usuario, a.fecha
               FROM public.cobros_ajustes a
              WHERE a.obligacion_id IN (SELECT obligacion_id FROM public.cobros_obligaciones WHERE estudiante_id = $1)
                 OR a.plan_id IN (SELECT plan_id FROM public.cobros_planes WHERE estudiante_id = $1)
              ORDER BY a.fecha DESC, a.ajuste_id DESC
              LIMIT 30`,
            [estudianteId]
        );

        // Resumen en centavos
        let base = 0, recargo = 0, total = 0, pagado = 0, vencido = 0, cuotasVencidas = 0, mesesMora = 0;
        let proxima = null;
        for (const c of cuotasRes.rows) {
            base += aCentavosDesdeDb(c.monto_base);
            recargo += aCentavosDesdeDb(c.recargo_acumulado);
            total += aCentavosDesdeDb(c.monto_total);
            pagado += aCentavosDesdeDb(c.monto_pagado);
            if (c.estado_real === "VENCIDO") {
                vencido += aCentavosDesdeDb(c.saldo);
                cuotasVencidas++;
            } else if (c.estado_real !== "PAGADO" && !proxima) {
                proxima = { obligacion_id: c.obligacion_id, concepto: c.concepto, fecha_vencimiento: c.fecha_vencimiento, saldo: c.saldo };
            }
        }
        const saldo = total - pagado;
        mesesMora = cuotasVencidas;

        res.json({
            estudiante: est.rows[0],
            resumen: {
                total_base: dinero(base),
                total_recargos: dinero(recargo),
                total_a_pagar: dinero(total),
                total_pagado: dinero(pagado),
                saldo: dinero(saldo),
                saldo_vencido: dinero(vencido),
                cuotas_vencidas: cuotasVencidas,
                meses_en_mora: mesesMora,
                total_cuotas: cuotasRes.rows.length,
                cuotas_pagadas: cuotasRes.rows.filter(c => c.estado_real === "PAGADO").length,
                proxima_cuota: proxima
            },
            cuotas: cuotasRes.rows,
            pagos: pagosRes.rows,
            ajustes: ajustesRes.rows
        });
    } catch (error) {
        responderError(res, error, "obtenerEstadoCuenta");
    }
}

/* ═══════════════════════════════════════════════════════════
   3. PUT /api/cobros/estudiantes/:id/pagar
   Pago acumulado: se reparte de la cuota más antigua a la más reciente.
   Si cubre una cuota y sobra, el resto pasa a la siguiente (puede quedar parcial).
   Todo en una sola transacción: o se aplica completo o no se aplica nada.
   ═══════════════════════════════════════════════════════════ */
async function registrarPagoAcumulado(req, res) {
    try {
        const estudianteId = String(req.params.id);
        const { metodo_pago } = req.body;
        const plan_id = req.body.plan_id === undefined || req.body.plan_id === null || req.body.plan_id === ""
            ? null : Number(req.body.plan_id);

        const montoC = aCentavos(req.body.monto, 100000);
        if (montoC === null) {
            throw falla(400, "monto debe ser mayor a 0 y tener máximo 2 decimales.");
        }
        if (metodo_pago && !METODOS_PAGO.includes(metodo_pago)) {
            throw falla(400, `metodo_pago debe ser uno de: ${METODOS_PAGO.join(", ")}.`);
        }
        if (plan_id !== null && (!Number.isInteger(plan_id) || plan_id < 1)) {
            throw falla(400, "plan_id inválido.");
        }

        const resultado = await conTransaccion(async (client) => {
            // Recargos al día ANTES de calcular saldos
            await aplicarRecargos(client, { estudianteId });

            const cuotasRes = await client.query(
                `SELECT obligacion_id, concepto, monto_total, monto_pagado
                   FROM public.cobros_obligaciones
                  WHERE estudiante_id = $1 AND estado <> 'PAGADO'
                    AND ($2::int IS NULL OR plan_id = $2::int)
                  ORDER BY fecha_vencimiento ASC, numero_cuota ASC NULLS LAST, obligacion_id ASC
                  FOR UPDATE`,
                [estudianteId, plan_id]
            );
            if (cuotasRes.rows.length === 0) {
                throw falla(400, "El estudiante no tiene cuotas pendientes de pago.");
            }

            const cuotas = cuotasRes.rows.map(c => ({
                obligacion_id: c.obligacion_id,
                concepto: c.concepto,
                saldoC: aCentavosDesdeDb(c.monto_total) - aCentavosDesdeDb(c.monto_pagado)
            }));
            const saldoTotalC = cuotas.reduce((acc, c) => acc + c.saldoC, 0);

            if (montoC > saldoTotalC) {
                throw falla(400, `El monto ($${dinero(montoC)}) excede la deuda total pendiente ($${dinero(saldoTotalC)}).`);
            }

            const { asignaciones } = distribuirPago(cuotas, montoC);
            const lote = crypto.randomUUID();
            const aplicado = [];
            for (const a of asignaciones) {
                const fila = await aplicarPago(client, a.obligacion_id, a.montoC, {
                    usuario: req.user.id, origen: "MANUAL", metodo: metodo_pago || null, lote, recargosAlDia: true
                });
                aplicado.push({
                    obligacion_id: a.obligacion_id,
                    concepto: cuotas.find(c => c.obligacion_id === a.obligacion_id)?.concepto,
                    monto: Number(dinero(a.montoC)),
                    saldo_restante: Number(dinero(a.saldoRestanteC)),
                    estado: fila.estado
                });
            }
            return { lote, aplicado, saldo_total_restante: Number(dinero(saldoTotalC - montoC)) };
        });

        const n = resultado.aplicado.length;
        res.json({
            message: `Pago de $${dinero(montoC)} aplicado en ${n} cuota${n === 1 ? "" : "s"}.`,
            ...resultado
        });
    } catch (error) {
        responderError(res, error, "registrarPagoAcumulado");
    }
}

/* ═══════════════════════════════════════════════════════════
   4. PUT /api/cobros/cuotas/:id   (editar monto, fecha o concepto de una cuota)
   ═══════════════════════════════════════════════════════════ */
async function editarCuota(req, res) {
    try {
        const id = Number(req.params.id);
        if (!Number.isInteger(id) || id < 1) throw falla(400, "Cuota inválida.");

        const { monto_base, fecha_vencimiento, concepto } = req.body;
        if (monto_base === undefined && fecha_vencimiento === undefined && concepto === undefined) {
            throw falla(400, "No hay nada que modificar.");
        }

        const resultado = await conTransaccion(async (client) => {
            const r = await client.query(
                `SELECT obligacion_id, estudiante_id, concepto, estado, monto_pagado, monto_total, recargo_acumulado,
                        COALESCE(monto_base, monto_total - recargo_acumulado) AS monto_base,
                        to_char(fecha_vencimiento::date, 'YYYY-MM-DD') AS fecha_iso, plan_id
                   FROM public.cobros_obligaciones WHERE obligacion_id = $1 FOR UPDATE`,
                [id]
            );
            if (r.rows.length === 0) throw falla(404, "Cuota no encontrada.");
            const actual = r.rows[0];
            if (actual.estado === "PAGADO") {
                throw falla(409, "La cuota ya está pagada y no se puede modificar.");
            }

            let nuevaBaseC = aCentavosDesdeDb(actual.monto_base);
            if (monto_base !== undefined) {
                const c = aCentavos(monto_base, MONTO_MAXIMO_CUOTA);
                if (c === null) {
                    throw falla(400, `monto_base debe ser mayor a 0, con máximo 2 decimales y no superar $${MONTO_MAXIMO_CUOTA}.`);
                }
                nuevaBaseC = c;
            }
            let nuevaFecha = actual.fecha_iso;
            if (fecha_vencimiento !== undefined) {
                nuevaFecha = parseFechaISO(fecha_vencimiento);
                if (!nuevaFecha) throw falla(400, "fecha_vencimiento no es una fecha válida.");
            }
            let nuevoConcepto = actual.concepto;
            if (concepto !== undefined) {
                nuevoConcepto = String(concepto).trim();
                if (nuevoConcepto.length < 3 || nuevoConcepto.length > 120) {
                    throw falla(400, "El concepto debe tener entre 3 y 120 caracteres.");
                }
                const dup = await client.query(
                    `SELECT 1 FROM public.cobros_obligaciones
                      WHERE estudiante_id = $1 AND LOWER(concepto) = LOWER($2) AND obligacion_id <> $3`,
                    [actual.estudiante_id, nuevoConcepto, id]
                );
                if (dup.rows.length > 0) throw falla(409, `El estudiante ya tiene una cuota con el concepto "${nuevoConcepto}".`);
            }

            const recargoC = aCentavosDesdeDb(actual.recargo_acumulado);
            const pagadoC = aCentavosDesdeDb(actual.monto_pagado);
            const nuevoTotalC = nuevaBaseC + recargoC;
            if (nuevoTotalC < pagadoC) {
                throw falla(400, `No puedes dejar la cuota por debajo de lo ya pagado ($${dinero(pagadoC)}).`);
            }
            const nuevoEstado = pagadoC === nuevoTotalC ? "PAGADO" : pagadoC > 0 ? "PARCIAL" : "PENDIENTE";

            const upd = await client.query(
                `UPDATE public.cobros_obligaciones
                    SET monto_base = $1, monto_total = $2, fecha_vencimiento = $3, concepto = $4, estado = $5,
                        fecha_pago = CASE WHEN $6::boolean THEN COALESCE(fecha_pago, NOW()) ELSE fecha_pago END
                  WHERE obligacion_id = $7 RETURNING *`,
                [nuevaBaseC / 100, nuevoTotalC / 100, nuevaFecha, nuevoConcepto, nuevoEstado, nuevoEstado === "PAGADO", id]
            );

            const cambios = [];
            if (nuevaBaseC !== aCentavosDesdeDb(actual.monto_base)) cambios.push(`base $${dinero(aCentavosDesdeDb(actual.monto_base))} → $${dinero(nuevaBaseC)}`);
            if (nuevaFecha !== actual.fecha_iso) cambios.push(`vence ${actual.fecha_iso} → ${nuevaFecha}`);
            if (nuevoConcepto !== actual.concepto) cambios.push(`concepto "${actual.concepto}" → "${nuevoConcepto}"`);
            if (cambios.length > 0) {
                await registrarAjuste(client, {
                    tipo: "EDICION", obligacion_id: id, plan_id: actual.plan_id,
                    detalle: cambios.join("; "), usuario: req.user.id
                });
            }
            return upd.rows[0];
        });

        res.json({ message: "Cuota actualizada.", cuota: resultado });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ error: "Conflicto al guardar la cuota." });
        }
        responderError(res, error, "editarCuota");
    }
}

/* ═══════════════════════════════════════════════════════════
   5. PUT /api/cobros/cuotas/:id/condonar-recargo
   Perdona el recargo que todavía no se ha pagado (queda en auditoría).
   ═══════════════════════════════════════════════════════════ */
async function condonarRecargo(req, res) {
    try {
        const id = Number(req.params.id);
        if (!Number.isInteger(id) || id < 1) throw falla(400, "Cuota inválida.");
        const motivo = req.body.motivo ? String(req.body.motivo).trim().slice(0, 200) : null;

        const resultado = await conTransaccion(async (client) => {
            const r = await client.query(
                `SELECT obligacion_id, estado, monto_total, monto_pagado, recargo_acumulado, plan_id
                   FROM public.cobros_obligaciones WHERE obligacion_id = $1 FOR UPDATE`,
                [id]
            );
            if (r.rows.length === 0) throw falla(404, "Cuota no encontrada.");
            const c = r.rows[0];
            if (c.estado === "PAGADO") throw falla(409, "La cuota ya está pagada.");

            const recargoC = aCentavosDesdeDb(c.recargo_acumulado);
            const totalC = aCentavosDesdeDb(c.monto_total);
            const pagadoC = aCentavosDesdeDb(c.monto_pagado);
            if (recargoC <= 0) throw falla(400, "La cuota no tiene recargo para condonar.");

            // Solo se puede perdonar lo que aún se debe; lo ya pagado no se devuelve
            const condonadoC = Math.min(recargoC, totalC - pagadoC);
            const nuevoTotalC = totalC - condonadoC;
            const nuevoRecargoC = recargoC - condonadoC;
            const nuevoEstado = pagadoC === nuevoTotalC ? "PAGADO" : pagadoC > 0 ? "PARCIAL" : "PENDIENTE";

            const upd = await client.query(
                `UPDATE public.cobros_obligaciones
                    SET monto_total = $1, recargo_acumulado = $2, estado = $3,
                        fecha_pago = CASE WHEN $4::boolean THEN COALESCE(fecha_pago, NOW()) ELSE fecha_pago END
                  WHERE obligacion_id = $5 RETURNING *`,
                [nuevoTotalC / 100, nuevoRecargoC / 100, nuevoEstado, nuevoEstado === "PAGADO", id]
            );
            await registrarAjuste(client, {
                tipo: "CONDONACION", obligacion_id: id, plan_id: c.plan_id, monto: condonadoC / 100,
                detalle: motivo ? `Recargo condonado. Motivo: ${motivo}` : "Recargo condonado", usuario: req.user.id
            });
            return { cuota: upd.rows[0], condonado: condonadoC / 100 };
        });

        res.json({ message: `Se condonó $${resultado.condonado.toFixed(2)} de recargo.`, ...resultado });
    } catch (error) {
        responderError(res, error, "condonarRecargo");
    }
}

/* ═══════════════════════════════════════════════════════════
   6. DELETE /api/cobros/planes/:id
   Solo si ninguna cuota tiene pagos ni comprobantes (no se borra historial financiero).
   ═══════════════════════════════════════════════════════════ */
async function eliminarPlan(req, res) {
    try {
        const id = Number(req.params.id);
        if (!Number.isInteger(id) || id < 1) throw falla(400, "Plan inválido.");

        const eliminado = await conTransaccion(async (client) => {
            const plan = await client.query(`SELECT * FROM public.cobros_planes WHERE plan_id = $1 FOR UPDATE`, [id]);
            if (plan.rows.length === 0) throw falla(404, "Plan no encontrado.");

            const cuotas = await client.query(
                `SELECT obligacion_id, monto_pagado, comprobante_estado FROM public.cobros_obligaciones
                  WHERE plan_id = $1 FOR UPDATE`,
                [id]
            );
            const conMovimientos = cuotas.rows.filter(c => parseFloat(c.monto_pagado) > 0 || c.comprobante_estado);
            if (conMovimientos.length > 0) {
                throw falla(409, `No se puede eliminar: ${conMovimientos.length} cuota(s) del plan tienen pagos o comprobantes registrados.`);
            }
            const pagos = await client.query(
                `SELECT 1 FROM public.cobros_pagos WHERE obligacion_id = ANY($1::int[]) LIMIT 1`,
                [cuotas.rows.map(c => c.obligacion_id)]
            );
            if (pagos.rows.length > 0) {
                throw falla(409, "No se puede eliminar: el plan tiene pagos en el historial.");
            }

            await client.query(`DELETE FROM public.cobros_obligaciones WHERE plan_id = $1`, [id]);
            await client.query(`DELETE FROM public.cobros_planes WHERE plan_id = $1`, [id]);
            await registrarAjuste(client, {
                tipo: "PLAN_ELIMINADO", plan_id: id,
                detalle: `Plan "${plan.rows[0].nombre}" eliminado (${cuotas.rows.length} cuotas sin movimientos)`,
                usuario: req.user.id
            });
            return { plan: plan.rows[0], cuotas: cuotas.rows.length };
        });

        res.json({ message: `Plan eliminado (${eliminado.cuotas} cuota(s)).` });
    } catch (error) {
        responderError(res, error, "eliminarPlan");
    }
}

/* ═══════════════════════════════════════════════════════════
   7. Configuración de recargos por mora
   ═══════════════════════════════════════════════════════════ */
async function obtenerConfiguracion(req, res) {
    try {
        const r = await pool.query(
            `SELECT recargo_activo, recargo_tipo, recargo_valor, recargo_tope_porcentaje,
                    to_char(recargo_desde, 'YYYY-MM-DD') AS recargo_desde, actualizado_en, actualizado_por
               FROM public.cobros_configuracion WHERE id = 1`
        );
        res.json(r.rows[0]);
    } catch (error) {
        responderError(res, error, "obtenerConfiguracion");
    }
}

async function actualizarConfiguracion(req, res) {
    try {
        const { recargo_activo, recargo_tipo, recargo_valor, recargo_tope_porcentaje, recargo_desde } = req.body;

        if (typeof recargo_activo !== "boolean") {
            throw falla(400, "recargo_activo debe ser verdadero o falso.");
        }
        if (!["PORCENTAJE", "FIJO"].includes(recargo_tipo)) {
            throw falla(400, "recargo_tipo debe ser PORCENTAJE o FIJO.");
        }
        const valor = Number(recargo_valor);
        const maxValor = recargo_tipo === "PORCENTAJE" ? 100 : 500;
        if (!Number.isFinite(valor) || valor < 0 || valor > maxValor || Math.round(valor * 100) / 100 !== valor) {
            throw falla(400, recargo_tipo === "PORCENTAJE"
                ? "El porcentaje debe estar entre 0 y 100, con máximo 2 decimales."
                : "El recargo fijo debe estar entre $0 y $500, con máximo 2 decimales.");
        }
        if (recargo_activo && valor <= 0) {
            throw falla(400, "Para activar los recargos, el valor debe ser mayor a 0.");
        }
        let tope = null;
        if (recargo_tope_porcentaje !== null && recargo_tope_porcentaje !== undefined && recargo_tope_porcentaje !== "") {
            tope = Number(recargo_tope_porcentaje);
            if (!Number.isFinite(tope) || tope <= 0 || tope > 500) {
                throw falla(400, "El tope debe estar entre 0 y 500 % de la cuota (o dejarlo vacío para no limitar).");
            }
        }

        const previa = await pool.query(`SELECT recargo_activo FROM public.cobros_configuracion WHERE id = 1`);
        let desde = null;
        if (recargo_desde) {
            desde = parseFechaISO(recargo_desde);
            if (!desde) throw falla(400, "recargo_desde no es una fecha válida.");
        } else if (recargo_activo && previa.rows[0] && !previa.rows[0].recargo_activo) {
            desde = new Date().toISOString().slice(0, 10); // al activar por primera vez: desde hoy
        }

        await pool.query(
            `UPDATE public.cobros_configuracion
                SET recargo_activo = $1, recargo_tipo = $2, recargo_valor = $3, recargo_tope_porcentaje = $4,
                    recargo_desde = COALESCE($5::date, recargo_desde),
                    actualizado_en = NOW(), actualizado_por = $6
              WHERE id = 1`,
            [recargo_activo, recargo_tipo, valor, tope, desde, String(req.user.id)]
        );
        await registrarAjuste(pool, {
            tipo: "CONFIGURACION",
            detalle: `Recargo ${recargo_activo ? "ACTIVO" : "inactivo"}: ${recargo_tipo === "PORCENTAJE" ? valor + " %" : "$" + valor.toFixed(2)} mensual`
                + (tope ? `, tope ${tope} %` : "") + (desde ? `, desde ${desde}` : ""),
            usuario: req.user.id
        });

        const aplicado = recargo_activo ? await aplicarRecargos(pool) : { cuotas: 0, total: 0 };
        const actual = await pool.query(
            `SELECT recargo_activo, recargo_tipo, recargo_valor, recargo_tope_porcentaje,
                    to_char(recargo_desde, 'YYYY-MM-DD') AS recargo_desde FROM public.cobros_configuracion WHERE id = 1`
        );
        res.json({ message: "Configuración guardada.", configuracion: actual.rows[0], aplicado });
    } catch (error) {
        responderError(res, error, "actualizarConfiguracion");
    }
}

/* ═══════════════════════════════════════════════════════════
   8. POST /api/cobros/recargos/aplicar  (ejecución manual; también corre solo a diario)
   ═══════════════════════════════════════════════════════════ */
async function ejecutarRecargos(req, res) {
    try {
        const cfg = await pool.query(`SELECT recargo_activo FROM public.cobros_configuracion WHERE id = 1`);
        if (!cfg.rows[0]?.recargo_activo) {
            return res.status(400).json({ error: "Los recargos por mora están desactivados. Actívalos en la configuración." });
        }
        const r = await aplicarRecargos(pool);
        if (r.cuotas > 0) {
            await registrarAjuste(pool, { tipo: "RECARGOS", monto: r.total, detalle: `Recargos cargados en ${r.cuotas} cuota(s)`, usuario: req.user.id });
        }
        res.json({
            message: r.cuotas > 0
                ? `Se cargaron $${r.total.toFixed(2)} de recargo en ${r.cuotas} cuota(s).`
                : "No había recargos nuevos que cargar.",
            ...r
        });
    } catch (error) {
        responderError(res, error, "ejecutarRecargos");
    }
}

module.exports = {
    crearPlan,
    obtenerEstadoCuenta,
    registrarPagoAcumulado,
    editarCuota,
    condonarRecargo,
    eliminarPlan,
    obtenerConfiguracion,
    actualizarConfiguracion,
    ejecutarRecargos,
    parseFechaISO
};
