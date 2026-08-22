// src/controllers/reportesControllers.js
const pool = require("../db");
const XLSX = require("xlsx");
const PDFDocument = require("pdfkit");

// Expresión SQL reutilizable: calcula el estado real de una obligación
// (PAGADO / VENCIDO / PARCIAL / PENDIENTE), igual que se calcula en el
// frontend (estado-cuenta-estudiante), para que Reportes sea consistente
// con lo que ve el estudiante.
const ESTADO_REAL_SQL = `
  CASE
    WHEN co.estado = 'PAGADO' THEN 'PAGADO'
    WHEN co.fecha_vencimiento < CURRENT_DATE THEN 'VENCIDO'
    WHEN co.monto_pagado > 0 THEN 'PARCIAL'
    ELSE 'PENDIENTE'
  END
`;

/**
 * Construye la cláusula WHERE + parámetros a partir de los filtros dinámicos
 * que puede mandar el frontend: fecha_inicio, fecha_fin, titulacion_id, estado.
 * Todas las consultas de este controller hacen JOIN con estudiantes (y
 * opcionalmente titulaciones), así que este helper asume alias co / e.
 */
function construirFiltros(query) {
  const { fecha_inicio, fecha_fin, titulacion_id, estado } = query;
  const condiciones = [];
  const params = [];

  if (fecha_inicio) {
    params.push(fecha_inicio);
    condiciones.push(`co.fecha_vencimiento >= $${params.length}`);
  }
  if (fecha_fin) {
    params.push(fecha_fin);
    condiciones.push(`co.fecha_vencimiento <= $${params.length}`);
  }
  if (titulacion_id) {
    params.push(titulacion_id);
    condiciones.push(`e.titulacion_id = $${params.length}`);
  }
  if (estado) {
    params.push(String(estado).toUpperCase());
    condiciones.push(`(${ESTADO_REAL_SQL}) = $${params.length}`);
  }

  const where = condiciones.length > 0 ? `WHERE ${condiciones.join(" AND ")}` : "";
  return { where, params };
}

/* ============================================================
   1. GET /api/reportes/resumen
   KPIs generales, respetando los filtros dinámicos
   ============================================================ */
async function obtenerResumen(req, res) {
  try {
    const { where, params } = construirFiltros(req.query);

    const result = await pool.query(
      `SELECT
          COALESCE(SUM(co.monto_pagado), 0)::numeric(10,2)               AS total_recaudado,
          COALESCE(SUM(co.monto_total - co.monto_pagado), 0)::numeric(10,2) AS total_pendiente,
          COUNT(*) FILTER (WHERE (${ESTADO_REAL_SQL}) IN ('PENDIENTE','PARCIAL'))::int AS obligaciones_pendientes,
          COUNT(*) FILTER (WHERE (${ESTADO_REAL_SQL}) = 'VENCIDO')::int   AS obligaciones_vencidas,
          COUNT(DISTINCT co.estudiante_id) FILTER (WHERE (${ESTADO_REAL_SQL}) = 'VENCIDO')::int AS estudiantes_morosos,
          CASE WHEN SUM(co.monto_total) > 0
               THEN ROUND(SUM(co.monto_pagado) / SUM(co.monto_total) * 100, 1)
               ELSE 0 END                                                AS efectividad_cobro
       FROM public.cobros_obligaciones co
       JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
       ${where}`,
      params
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("🔴 obtenerResumen (reportes):", error);
    res.status(500).json({ error: "Error al calcular el resumen del reporte." });
  }
}

/* ============================================================
   2. GET /api/reportes/serie-mensual
   Recaudado vs. pendiente por mes — para el gráfico de líneas/barras
   ============================================================ */
async function obtenerSerieMensual(req, res) {
  try {
    const { where, params } = construirFiltros(req.query);

    const result = await pool.query(
      `SELECT
          to_char(date_trunc('month', co.fecha_vencimiento), 'YYYY-MM') AS mes,
          COALESCE(SUM(co.monto_pagado), 0)::numeric(10,2)                AS recaudado,
          COALESCE(SUM(co.monto_total - co.monto_pagado), 0)::numeric(10,2) AS pendiente
       FROM public.cobros_obligaciones co
       JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
       ${where}
       GROUP BY 1
       ORDER BY 1`,
      params
    );

    res.json(result.rows);
  } catch (error) {
    console.error("🔴 obtenerSerieMensual:", error);
    res.status(500).json({ error: "Error al calcular la serie mensual." });
  }
}

/* ============================================================
   3. GET /api/reportes/por-titulacion
   Recaudado vs. pendiente agrupado por titulación — gráfico de barras
   ============================================================ */
async function obtenerPorTitulacion(req, res) {
  try {
    const { where, params } = construirFiltros(req.query);

    const result = await pool.query(
      `SELECT
          COALESCE(t.nombre_titulacion, 'Sin titulación')                  AS titulacion,
          COALESCE(SUM(co.monto_pagado), 0)::numeric(10,2)                 AS recaudado,
          COALESCE(SUM(co.monto_total - co.monto_pagado), 0)::numeric(10,2) AS pendiente
       FROM public.cobros_obligaciones co
       JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
       LEFT JOIN public.titulaciones t ON e.titulacion_id = t.titulacion_id
       ${where}
       GROUP BY t.nombre_titulacion
       ORDER BY recaudado DESC`,
      params
    );

    res.json(result.rows);
  } catch (error) {
    console.error("🔴 obtenerPorTitulacion:", error);
    res.status(500).json({ error: "Error al calcular el reporte por titulación." });
  }
}

/* ============================================================
   4. GET /api/reportes/por-estado
   Distribución de obligaciones por estado — gráfico de dona/torta
   ============================================================ */
async function obtenerPorEstado(req, res) {
  try {
    const { where, params } = construirFiltros(req.query);

    const result = await pool.query(
      `SELECT
          (${ESTADO_REAL_SQL})                                              AS estado,
          COUNT(*)::int                                                     AS cantidad,
          COALESCE(SUM(co.monto_total - co.monto_pagado), 0)::numeric(10,2) AS monto_pendiente
       FROM public.cobros_obligaciones co
       JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
       ${where}
       GROUP BY 1
       ORDER BY cantidad DESC`,
      params
    );

    res.json(result.rows);
  } catch (error) {
    console.error("🔴 obtenerPorEstado:", error);
    res.status(500).json({ error: "Error al calcular la distribución por estado." });
  }
}

/* ============================================================
   5. GET /api/reportes/obligaciones
   Tabla paginada y filtrable (reemplaza el "últimos 10" fijo)
   Filtros: fecha_inicio, fecha_fin, titulacion_id, estado, busqueda, page, limit
   ============================================================ */
async function obtenerObligacionesFiltradas(req, res) {
  try {
    const { where, params } = construirFiltros(req.query);

    const page  = Math.max(parseInt(req.query.page)  || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 100);
    const offset = (page - 1) * limit;

    let whereFinal = where;
    const paramsBase = [...params];
    if (req.query.busqueda) {
      paramsBase.push(`%${req.query.busqueda}%`);
      whereFinal += (whereFinal ? " AND " : "WHERE ") +
        `(e.nombre ILIKE $${paramsBase.length} OR e.apellido ILIKE $${paramsBase.length} OR e.codigo_estudiante ILIKE $${paramsBase.length})`;
    }

    const totalResult = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM public.cobros_obligaciones co
       JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
       ${whereFinal}`,
      paramsBase
    );

    const dataParams = [...paramsBase, limit, offset];
    const dataResult = await pool.query(
      `SELECT co.obligacion_id, co.fecha_vencimiento, co.fecha_pago,
              co.monto_total, co.monto_pagado,
              (co.monto_total - co.monto_pagado) AS saldo_pendiente,
              (${ESTADO_REAL_SQL})                AS estado,
              e.estudiante_id, e.nombre, e.apellido, e.codigo_estudiante,
              t.nombre_titulacion
       FROM public.cobros_obligaciones co
       JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
       LEFT JOIN public.titulaciones t ON e.titulacion_id = t.titulacion_id
       ${whereFinal}
       ORDER BY co.fecha_vencimiento DESC
       LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`,
      dataParams
    );

    const total = totalResult.rows[0].total;
    res.json({
      data: dataResult.rows,
      total,
      page,
      totalPaginas: Math.max(Math.ceil(total / limit), 1)
    });
  } catch (error) {
    console.error("🔴 obtenerObligacionesFiltradas:", error);
    res.status(500).json({ error: "Error al obtener las obligaciones filtradas." });
  }
}

/* ============================================================
   Helper interno compartido por los dos exportadores:
   trae resumen + detalle completo (sin paginar) según los filtros
   ============================================================ */
async function obtenerDatosParaExportar(query) {
  const { where, params } = construirFiltros(query);

  const resumenResult = await pool.query(
    `SELECT
        COALESCE(SUM(co.monto_pagado), 0)::numeric(10,2)                 AS total_recaudado,
        COALESCE(SUM(co.monto_total - co.monto_pagado), 0)::numeric(10,2) AS total_pendiente,
        COUNT(*) FILTER (WHERE (${ESTADO_REAL_SQL}) IN ('PENDIENTE','PARCIAL'))::int AS obligaciones_pendientes,
        COUNT(*) FILTER (WHERE (${ESTADO_REAL_SQL}) = 'VENCIDO')::int    AS obligaciones_vencidas,
        COUNT(DISTINCT co.estudiante_id) FILTER (WHERE (${ESTADO_REAL_SQL}) = 'VENCIDO')::int AS estudiantes_morosos,
        CASE WHEN SUM(co.monto_total) > 0
             THEN ROUND(SUM(co.monto_pagado) / SUM(co.monto_total) * 100, 1)
             ELSE 0 END                                                  AS efectividad_cobro
     FROM public.cobros_obligaciones co
     JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
     ${where}`,
    params
  );

  const detalleResult = await pool.query(
    `SELECT co.obligacion_id, co.fecha_vencimiento, co.fecha_pago,
            co.monto_total, co.monto_pagado,
            (co.monto_total - co.monto_pagado) AS saldo_pendiente,
            (${ESTADO_REAL_SQL})                AS estado,
            e.codigo_estudiante, e.nombre, e.apellido,
            t.nombre_titulacion
     FROM public.cobros_obligaciones co
     JOIN public.estudiantes e ON co.estudiante_id = e.estudiante_id
     LEFT JOIN public.titulaciones t ON e.titulacion_id = t.titulacion_id
     ${where}
     ORDER BY co.fecha_vencimiento DESC`,
    params
  );

  return { resumen: resumenResult.rows[0], detalle: detalleResult.rows };
}

function describirFiltros(query) {
  const partes = [];
  if (query.fecha_inicio) partes.push(`Desde ${query.fecha_inicio}`);
  if (query.fecha_fin) partes.push(`Hasta ${query.fecha_fin}`);
  if (query.estado) partes.push(`Estado: ${query.estado}`);
  if (query.titulacion_id) partes.push(`Titulación #${query.titulacion_id}`);
  return partes.length > 0 ? partes.join("  ·  ") : "Sin filtros (todos los registros)";
}

/* ============================================================
   6. GET /api/reportes/exportar/excel
   Genera un .xlsx real en el servidor con 2 hojas: Resumen y Obligaciones
   ============================================================ */
async function exportarExcel(req, res) {
  try {
    const { resumen, detalle } = await obtenerDatosParaExportar(req.query);

    const wb = XLSX.utils.book_new();

    // Hoja 1: Resumen
    const filasResumen = [
      ["Instituto Nova Cuisine — Reporte Financiero"],
      [`Generado: ${new Date().toLocaleString("es-EC")}`],
      [`Filtros: ${describirFiltros(req.query)}`],
      [],
      ["Indicador", "Valor"],
      ["Total Recaudado", Number(resumen.total_recaudado)],
      ["Total Pendiente", Number(resumen.total_pendiente)],
      ["Obligaciones Pendientes/Parciales", resumen.obligaciones_pendientes],
      ["Obligaciones Vencidas", resumen.obligaciones_vencidas],
      ["Estudiantes Morosos", resumen.estudiantes_morosos],
      ["Efectividad de Cobro (%)", Number(resumen.efectividad_cobro)]
    ];
    const wsResumen = XLSX.utils.aoa_to_sheet(filasResumen);
    wsResumen["!cols"] = [{ wch: 32 }, { wch: 18 }];
    XLSX.utils.book_append_sheet(wb, wsResumen, "Resumen");

    // Hoja 2: Detalle de obligaciones
    const filasDetalle = detalle.map(d => ({
      "Código": d.codigo_estudiante,
      "Estudiante": `${d.nombre} ${d.apellido}`,
      "Titulación": d.nombre_titulacion || "Sin titulación",
      "Vencimiento": d.fecha_vencimiento ? new Date(d.fecha_vencimiento).toLocaleDateString("es-EC") : "",
      "Fecha de Pago": d.fecha_pago ? new Date(d.fecha_pago).toLocaleDateString("es-EC") : "—",
      "Monto Total": Number(d.monto_total),
      "Monto Pagado": Number(d.monto_pagado),
      "Saldo Pendiente": Number(d.saldo_pendiente),
      "Estado": d.estado
    }));
    const wsDetalle = XLSX.utils.json_to_sheet(filasDetalle);
    wsDetalle["!cols"] = [
      { wch: 12 }, { wch: 24 }, { wch: 20 }, { wch: 12 },
      { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 14 }, { wch: 12 }
    ];
    XLSX.utils.book_append_sheet(wb, wsDetalle, "Obligaciones");

    const buffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

    res.setHeader("Content-Disposition", `attachment; filename="reporte-financiero-${Date.now()}.xlsx"`);
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.send(buffer);
  } catch (error) {
    console.error("🔴 exportarExcel:", error);
    res.status(500).json({ error: "Error al generar el archivo Excel." });
  }
}

/**
 * Dibuja una tabla simple (encabezado + filas alternadas + salto de página
 * automático) en un PDFDocument de pdfkit. pdfkit no trae tablas nativas,
 * así que se posiciona cada celda manualmente por x/y.
 */
function dibujarTabla(doc, startY, headers, rows, columnWidths) {
  const startX = doc.page.margins.left;
  const totalWidth = columnWidths.reduce((a, b) => a + b, 0);
  const rowHeight = 18;
  const pageBottom = doc.page.height - doc.page.margins.bottom;
  let y = startY;

  function dibujarEncabezado() {
    doc.rect(startX, y, totalWidth, rowHeight).fill("#1a1a1a");
    doc.fillColor("#f6f5f7").font("Helvetica-Bold").fontSize(8);
    let x = startX;
    headers.forEach((h, i) => {
      doc.text(h, x + 4, y + 5, { width: columnWidths[i] - 8, height: rowHeight - 6, ellipsis: true, lineBreak: false });
      x += columnWidths[i];
    });
    y += rowHeight;
  }

  dibujarEncabezado();
  doc.font("Helvetica").fontSize(8);

  rows.forEach((fila, idx) => {
    if (y + rowHeight > pageBottom) {
      doc.addPage();
      y = doc.page.margins.top;
      dibujarEncabezado();
      doc.font("Helvetica").fontSize(8);
    }

    if (idx % 2 === 0) {
      doc.rect(startX, y, totalWidth, rowHeight).fill("#f7f7f7");
    }
    doc.fillColor("#1a1a1a");
    let x = startX;
    fila.forEach((valor, i) => {
      doc.text(String(valor), x + 4, y + 5, { width: columnWidths[i] - 8, height: rowHeight - 6, ellipsis: true, lineBreak: false });
      x += columnWidths[i];
    });
    y += rowHeight;
  });

  return y;
}

/* ============================================================
   7. GET /api/reportes/exportar/pdf
   Genera un .pdf real en el servidor con encabezado, KPIs y tabla
   ============================================================ */
async function exportarPdf(req, res) {
  try {
    const { resumen, detalle } = await obtenerDatosParaExportar(req.query);

    const doc = new PDFDocument({ margin: 40, size: "A4" });

    res.setHeader("Content-Disposition", `attachment; filename="reporte-financiero-${Date.now()}.pdf"`);
    res.setHeader("Content-Type", "application/pdf");
    doc.pipe(res);

    // Encabezado
    doc.fillColor("#1a1a1a").font("Helvetica-Bold").fontSize(20).text("Nova Cuisine");
    doc.fillColor("#b8860b").font("Helvetica-Bold").fontSize(13).text("Reporte Financiero");
    doc.moveDown(0.3);
    doc.fillColor("#666666").font("Helvetica").fontSize(8);
    doc.text(`Generado: ${new Date().toLocaleString("es-EC")}`);
    doc.text(`Filtros: ${describirFiltros(req.query)}`);
    doc.moveDown(0.8);

    // Línea divisoria
    doc.moveTo(40, doc.y).lineTo(doc.page.width - 40, doc.y).strokeColor("#b8860b").lineWidth(1.5).stroke();
    doc.moveDown(0.8);

    // KPIs
    doc.fillColor("#1a1a1a").font("Helvetica-Bold").fontSize(11).text("Resumen");
    doc.moveDown(0.3);
    doc.fontSize(9);
    const kpis = [
      ["Total Recaudado", `$${Number(resumen.total_recaudado).toFixed(2)}`],
      ["Total Pendiente", `$${Number(resumen.total_pendiente).toFixed(2)}`],
      ["Obligaciones Pendientes/Parciales", `${resumen.obligaciones_pendientes}`],
      ["Obligaciones Vencidas", `${resumen.obligaciones_vencidas}`],
      ["Estudiantes Morosos", `${resumen.estudiantes_morosos}`],
      ["Efectividad de Cobro", `${resumen.efectividad_cobro}%`]
    ];
    kpis.forEach(([label, valor]) => {
      doc.font("Helvetica-Bold").text(`${label}: `, { continued: true }).font("Helvetica").text(valor);
    });
    doc.moveDown(1);

    // Tabla de detalle
    doc.font("Helvetica-Bold").fontSize(11).text(`Detalle de Obligaciones (${detalle.length})`);
    doc.moveDown(0.4);

    const headers = ["Código", "Estudiante", "Titulación", "Vence", "Total", "Pagado", "Estado"];
    const columnWidths = [52, 105, 130, 55, 55, 55, 63]; // suma 515 (A4 con márgenes 40+40)
    const rows = detalle.map(d => [
      d.codigo_estudiante,
      `${d.nombre} ${d.apellido}`,
      d.nombre_titulacion || "N/A",
      d.fecha_vencimiento ? new Date(d.fecha_vencimiento).toLocaleDateString("es-EC") : "",
      `$${Number(d.monto_total).toFixed(2)}`,
      `$${Number(d.monto_pagado).toFixed(2)}`,
      d.estado
    ]);

    if (rows.length > 0) {
      dibujarTabla(doc, doc.y, headers, rows, columnWidths);
    } else {
      doc.font("Helvetica").fontSize(9).fillColor("#888888").text("No hay obligaciones que coincidan con estos filtros.");
    }

    doc.end();
  } catch (error) {
    console.error("🔴 exportarPdf:", error);
    // Si ya se empezó a escribir el PDF en la respuesta no se puede mandar JSON,
    // así que solo se responde con error si la exportación falló antes de doc.pipe(res).
    if (!res.headersSent) {
      res.status(500).json({ error: "Error al generar el archivo PDF." });
    } else {
      res.end();
    }
  }
}

module.exports = {
  obtenerResumen,
  obtenerSerieMensual,
  obtenerPorTitulacion,
  obtenerPorEstado,
  obtenerObligacionesFiltradas,
  exportarExcel,
  exportarPdf
};
