// src/utils/cobrosCore.js
// Lógica central de cobros reutilizable: recargos por mora, reparto de un pago entre
// cuotas y expresiones SQL compartidas. Todo el dinero se maneja en CENTAVOS enteros.

const pool = require("../db");

/**
 * Estado "real" de una cuota (PAGADO / VENCIDO / PARCIAL / PENDIENTE).
 * Misma regla que usan Reportes y el estado de cuenta del estudiante.
 */
const estadoRealSql = (alias = "co") => `
  CASE
    WHEN ${alias}.estado = 'PAGADO' THEN 'PAGADO'
    WHEN ${alias}.fecha_vencimiento::date < CURRENT_DATE THEN 'VENCIDO'
    WHEN ${alias}.monto_pagado > 0 THEN 'PARCIAL'
    ELSE 'PENDIENTE'
  END`;

const aCentavosDesdeDb = (valor) => Math.round(parseFloat(valor ?? 0) * 100);

/**
 * Reparte un pago (en centavos) entre cuotas, de la más antigua a la más reciente.
 * `cuotas` debe venir ya ordenada: [{ obligacion_id, saldoC }].
 * Devuelve { asignaciones: [{ obligacion_id, montoC, saldoRestanteC }], sobranteC }.
 * Función pura (sin base de datos) para poder probarla de forma aislada.
 */
function distribuirPago(cuotas, montoC) {
    let restante = montoC;
    const asignaciones = [];
    for (const c of cuotas) {
        if (restante <= 0) break;
        if (c.saldoC <= 0) continue;
        const aplicar = Math.min(restante, c.saldoC);
        asignaciones.push({
            obligacion_id: c.obligacion_id,
            montoC: aplicar,
            saldoRestanteC: c.saldoC - aplicar
        });
        restante -= aplicar;
    }
    return { asignaciones, sobranteC: restante };
}

/**
 * Carga los recargos por mora que correspondan y todavía no estén aplicados.
 *
 * Regla (configurable en cobros_configuracion):
 *  - Una cuota no pagada y vencida genera un recargo por CADA MES COMPLETO transcurrido
 *    desde max(fecha de vencimiento, recargo_desde). Es acumulativo: mes 1, mes 2, mes 3…
 *  - PORCENTAJE: % sobre la parte de la cuota base que aún no se ha pagado (no hay interés
 *    sobre interés). FIJO: un valor fijo por mes.
 *  - Si la parte base ya está pagada, el recargo deja de crecer.
 *  - recargo_tope_porcentaje (opcional): el recargo total de una cuota no supera ese % de su base.
 *  - Es IDEMPOTENTE: recargo_meses_aplicados recuerda cuántos meses ya se cargaron, por lo que
 *    ejecutarlo varias veces el mismo día no duplica nada.
 *
 * @param client  pool o cliente (si se pasa un cliente en transacción, se usa su conexión)
 * @param opts    { estudianteId, obligacionId, hoy: 'YYYY-MM-DD' (solo para pruebas) }
 * @returns       { cuotas, total }  cuotas afectadas y total cargado en dólares
 */
async function aplicarRecargos(client = pool, { estudianteId = null, obligacionId = null, hoy = null } = {}) {
    const r = await client.query(
        `WITH cfg AS (
             SELECT * FROM public.cobros_configuracion WHERE id = 1 AND recargo_activo
         ),
         base AS (
             SELECT co.obligacion_id,
                    COALESCE(co.monto_base, co.monto_total - co.recargo_acumulado) AS monto_base,
                    co.monto_pagado,
                    co.recargo_acumulado,
                    co.recargo_meses_aplicados,
                    GREATEST(co.fecha_vencimiento::date, cfg.recargo_desde) AS inicio,
                    cfg.recargo_tipo, cfg.recargo_valor, cfg.recargo_tope_porcentaje
               FROM public.cobros_obligaciones co
               CROSS JOIN cfg
              WHERE co.estado <> 'PAGADO'
                AND ($2::text IS NULL OR co.estudiante_id::text = $2::text)
                AND ($3::int  IS NULL OR co.obligacion_id = $3::int)
         ),
         meses AS (
             SELECT b.*,
                    (EXTRACT(YEAR  FROM age(COALESCE($1::date, CURRENT_DATE), b.inicio)) * 12
                   + EXTRACT(MONTH FROM age(COALESCE($1::date, CURRENT_DATE), b.inicio)))::int AS meses_vencidos
               FROM base b
              WHERE b.inicio < COALESCE($1::date, CURRENT_DATE)
         ),
         calc AS (
             SELECT m.obligacion_id, m.monto_base, m.meses_vencidos,
                    GREATEST(m.meses_vencidos - m.recargo_meses_aplicados, 0) AS meses_nuevos,
                    CASE WHEN m.monto_base - m.monto_pagado <= 0 THEN 0
                         WHEN m.recargo_tipo = 'PORCENTAJE'
                              THEN ROUND(m.recargo_valor / 100 * (m.monto_base - m.monto_pagado), 2)
                         ELSE m.recargo_valor
                    END AS por_mes,
                    m.recargo_acumulado, m.recargo_tope_porcentaje
               FROM meses m
              WHERE m.meses_vencidos > m.recargo_meses_aplicados
         ),
         final AS (
             SELECT c.obligacion_id, c.monto_base, c.meses_vencidos,
                    CASE WHEN c.recargo_tope_porcentaje IS NULL
                         THEN c.meses_nuevos * c.por_mes
                         ELSE LEAST(
                                c.meses_nuevos * c.por_mes,
                                GREATEST(ROUND(c.monto_base * c.recargo_tope_porcentaje / 100, 2) - c.recargo_acumulado, 0)
                              )
                    END AS incremento
               FROM calc c
         )
         UPDATE public.cobros_obligaciones co
            SET recargo_acumulado       = co.recargo_acumulado + f.incremento,
                monto_total             = co.monto_total + f.incremento,
                recargo_meses_aplicados = f.meses_vencidos,
                monto_base              = f.monto_base
           FROM final f
          WHERE co.obligacion_id = f.obligacion_id
            -- En READ COMMITTED, si otra transacción cargó el recargo mientras esperábamos el bloqueo de
            -- la fila, esta condición se vuelve a evaluar y evita cobrar el mismo mes dos veces.
            AND co.recargo_meses_aplicados < f.meses_vencidos
          RETURNING co.obligacion_id, f.incremento`,
        [hoy, estudianteId === null ? null : String(estudianteId), obligacionId]
    );

    const total = r.rows.reduce((acc, row) => acc + parseFloat(row.incremento), 0);
    return { cuotas: r.rows.filter(x => parseFloat(x.incremento) > 0).length, total: Math.round(total * 100) / 100 };
}

// Aplicación "perezosa" con enfriamiento: los listados la llaman, pero como mucho 1 vez por minuto.
let ultimaAplicacion = 0;
async function aplicarRecargosSiToca(client = pool, enfriamientoMs = 60000) {
    const ahora = Date.now();
    if (ahora - ultimaAplicacion < enfriamientoMs) return null;
    ultimaAplicacion = ahora;
    try {
        return await aplicarRecargos(client);
    } catch (error) {
        ultimaAplicacion = 0; // reintentar en la próxima petición
        if (error.code === "42P01" || error.code === "42703") {
            // La migración 03 aún no se ejecutó: no tumbar el listado por esto
            return null;
        }
        throw error;
    }
}

/** Registra un movimiento en la auditoría de cobros (no interrumpe el flujo si falla). */
async function registrarAjuste(client, { tipo, obligacion_id = null, plan_id = null, monto = null, detalle = null, usuario = null }) {
    try {
        await client.query(
            `INSERT INTO public.cobros_ajustes (tipo, obligacion_id, plan_id, monto, detalle, usuario)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [tipo, obligacion_id, plan_id, monto, detalle ? String(detalle).slice(0, 400) : null, usuario === null ? null : String(usuario)]
        );
    } catch (error) {
        console.error("⚠️ No se pudo registrar el ajuste de cobros:", error.message);
    }
}

module.exports = {
    estadoRealSql,
    aCentavosDesdeDb,
    distribuirPago,
    aplicarRecargos,
    aplicarRecargosSiToca,
    registrarAjuste
};
