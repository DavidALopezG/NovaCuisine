// src/controllers/recetasControllers.js
const pool = require("../db");
const PDFDocument = require("pdfkit");
const { numeroEnRango, enteroPositivo } = require("../utils/validaciones");

const CANTIDAD_MAXIMA_INSUMO = 100000;
const PRECIO_MAXIMO = 100000;
const MAX_INGREDIENTES = 100;

/* ============================================================
   Utilidad: ejecutar una función dentro de una transacción
   usando UN SOLO cliente (evita el bug de pool.query('BEGIN'))
   ============================================================ */
async function conTransaccion(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const resultado = await fn(client);
    await client.query("COMMIT");
    return resultado;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Un Docente solo puede modificar/eliminar/versionar las recetas que él creó.
 * El Administrador puede con cualquiera. Devuelve { ok: true } o { ok: false, status, error }.
 */
async function verificarPropiedadReceta(req, recetaId) {
  const r = await pool.query(
    `SELECT usuario_creador_id FROM public.recetas WHERE receta_id = $1`,
    [recetaId]
  );
  if (r.rows.length === 0) {
    return { ok: false, status: 404, error: "Receta no encontrada." };
  }
  if (req.user.rol === 2 && String(r.rows[0].usuario_creador_id) !== String(req.user.id)) {
    return { ok: false, status: 403, error: "Solo puedes modificar las recetas que tú creaste." };
  }
  return { ok: true };
}

/** Valida nombre / porciones / tiempo de una receta. Devuelve mensaje o null. */
function validarCamposReceta({ nombre, porciones, tiempo_prep_min }) {
  const n = String(nombre || "").trim();
  if (n.length < 3 || n.length > 120) return "El nombre de la receta debe tener entre 3 y 120 caracteres.";
  const p = Number(porciones);
  if (!Number.isInteger(p) || p < 1 || p > 500) return "porciones debe ser un entero entre 1 y 500.";
  if (tiempo_prep_min !== undefined && tiempo_prep_min !== null && tiempo_prep_min !== "") {
    const t = Number(tiempo_prep_min);
    if (!Number.isFinite(t) || t < 0 || t > 1440) return "tiempo_prep_min debe estar entre 0 y 1440 minutos.";
  }
  return null;
}

/** precio_venta_sugerido es opcional; si viene debe estar entre 0 y PRECIO_MAXIMO. */
function validarPrecio(precio) {
  if (precio === undefined || precio === null || precio === "") return null;
  return numeroEnRango(precio, { min: 0, max: PRECIO_MAXIMO })
    ? null
    : `precio_venta_sugerido debe ser un número entre 0 y ${PRECIO_MAXIMO}.`;
}

/**
 * Valida la lista de ingredientes: ids válidos y sin repetir, cantidad > 0
 * (salvo "al gusto", que se guarda como 0) y que cada insumo exista.
 * Devuelve un mensaje de error o null.
 */
async function validarInsumosReceta(insumos) {
  if (insumos === undefined || insumos === null) return null;
  if (!Array.isArray(insumos)) return "insumos debe ser una lista.";
  if (insumos.length > MAX_INGREDIENTES) {
    return `Una receta no puede tener más de ${MAX_INGREDIENTES} ingredientes.`;
  }

  const ids = new Set();
  for (let i = 0; i < insumos.length; i++) {
    const item = insumos[i];
    const pos = `Ingrediente #${i + 1}`;
    if (!item || !enteroPositivo(item.insumo_id)) return `${pos}: insumo_id inválido.`;
    const id = Number(item.insumo_id);
    if (ids.has(id)) return `${pos}: el insumo está repetido en la receta.`;
    ids.add(id);
    if (!item.es_al_gusto &&
        !numeroEnRango(item.cantidad, { min: 0, max: CANTIDAD_MAXIMA_INSUMO, minExclusivo: true })) {
      return `${pos}: la cantidad debe ser mayor a 0 (o márcalo como "al gusto").`;
    }
  }

  if (ids.size > 0) {
    const r = await pool.query(
      `SELECT insumo_id FROM public.insumos_costos WHERE insumo_id = ANY($1::int[])`,
      [[...ids]]
    );
    if (r.rows.length !== ids.size) return "Alguno de los insumos seleccionados no existe.";
  }
  return null;
}

/**
 * Comprueba que la asignatura exista (si se indicó) y que no haya otra receta con el
 * mismo nombre dentro de esa asignatura. Devuelve { status, error } o null si todo está bien.
 */
async function validarAsignaturaYDuplicado({ nombre, asignatura_id, excluirRecetaId = null }) {
  const tieneAsignatura = asignatura_id !== undefined && asignatura_id !== null && asignatura_id !== "";
  if (tieneAsignatura) {
    if (!enteroPositivo(asignatura_id)) return { status: 400, error: "asignatura_id inválido." };
    const a = await pool.query(
      `SELECT 1 FROM public.asignaturas WHERE asignatura_id = $1`, [asignatura_id]
    );
    if (a.rows.length === 0) return { status: 404, error: "La asignatura seleccionada no existe." };
  }

  const dup = await pool.query(
    `SELECT 1 FROM public.recetas
      WHERE LOWER(TRIM(nombre)) = LOWER(TRIM($1))
        AND asignatura_id IS NOT DISTINCT FROM $2::int
        AND ($3::int IS NULL OR receta_id <> $3::int)`,
    [nombre, tieneAsignatura ? Number(asignatura_id) : null, excluirRecetaId]
  );
  if (dup.rows.length > 0) {
    return { status: 409, error: "Ya existe una receta con ese nombre en esa asignatura." };
  }
  return null;
}

/* ============================================================
   1. POST /api/recetas
   Crea la ficha maestra + su primera versión (1.0, BORRADOR)
   body: { nombre, porciones, tiempo_prep_min, asignatura_id,
           contenido_json, precio_venta_sugerido,
           insumos: [{insumo_id, cantidad}] }
   ============================================================ */
async function crearReceta(req, res) {
  const {
    nombre,
    porciones,
    tiempo_prep_min,
    asignatura_id,
    contenido_json,
    precio_venta_sugerido,
    insumos,
  } = req.body;

  if (!nombre || !porciones) {
    return res.status(400).json({ error: "nombre y porciones son obligatorios." });
  }
  const errorCampos = validarCamposReceta({ nombre, porciones, tiempo_prep_min });
  if (errorCampos) {
    return res.status(400).json({ error: errorCampos });
  }
  const errorPrecio = validarPrecio(precio_venta_sugerido);
  if (errorPrecio) {
    return res.status(400).json({ error: errorPrecio });
  }

  try {
    const errorInsumos = await validarInsumosReceta(insumos);
    if (errorInsumos) {
      return res.status(400).json({ error: errorInsumos });
    }
    const conflicto = await validarAsignaturaYDuplicado({ nombre, asignatura_id });
    if (conflicto) {
      return res.status(conflicto.status).json({ error: conflicto.error });
    }

    const usuario_creador_id = req.user.id;

    const resultado = await conTransaccion(async (client) => {
      const recetaResult = await client.query(
        `INSERT INTO public.recetas
            (nombre, porciones, tiempo_prep_min, asignatura_id, usuario_creador_id)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [String(nombre).trim(), porciones, tiempo_prep_min || null, asignatura_id || null, usuario_creador_id]
      );
      const receta = recetaResult.rows[0];

      const versionResult = await client.query(
        `INSERT INTO public.recetas_versiones
            (receta_id, numero_version, contenido_json, precio_venta_sugerido, estado)
         VALUES ($1, '1.0', $2, $3, 'BORRADOR')
         RETURNING *`,
        [receta.receta_id, contenido_json || null, precio_venta_sugerido || 0]
      );
      let version = versionResult.rows[0];

      if (Array.isArray(insumos)) {
        for (const item of insumos) {
          // La columna "cantidad" es NUMERIC NOT NULL en receta_version_insumos
          // (no existe columna es_al_gusto en la BD real). Un ingrediente marcado
          // como "al gusto / c/n" (ej. canela, aceite para freír) se guarda como
          // cantidad = 0: el trigger de costo lo trata como $0 de aporte, y el
          // frontend interpreta cantidad === 0 como "al gusto" al mostrarlo.
          const cantidadFinal = item.es_al_gusto ? 0 : item.cantidad;
          await client.query(
            `INSERT INTO public.receta_version_insumos (version_id, insumo_id, cantidad)
             VALUES ($1, $2, $3)`,
            [version.version_id, item.insumo_id, cantidadFinal]
          );
        }
      }

      // El trigger trg_costo_version recalcula costo_unitario al insertar insumos.
      // Releemos la versión para devolver el costo ya actualizado.
      const versionActualizada = await client.query(
        `SELECT * FROM public.recetas_versiones WHERE version_id = $1`,
        [version.version_id]
      );
      version = versionActualizada.rows[0];

      return { receta, version };
    });

    res.status(201).json({
      message: "Receta creada correctamente con su versión inicial 1.0.",
      receta: resultado.receta,
      version: resultado.version,
    });
  } catch (error) {
    console.error("🔴 Error al crear receta:", error);
    res.status(500).json({ error: "Error interno al crear la receta." });
  }
}

/* ============================================================
   2. GET /api/recetas
   Lista todas las recetas con la info de su última versión
   (recetario maestro: vista de docente/admin)
   ============================================================ */
async function obtenerRecetas(req, res) {
  try {
    const result = await pool.query(
      `SELECT
          r.receta_id, r.nombre, r.porciones, r.tiempo_prep_min, r.fecha_creacion,
          a.asignatura_id, a.nombre_asignatura, a.titulacion_id,
          u.nombre_completo AS autor,
          v.version_id, v.numero_version, v.estado AS estado_version,
          v.costo_unitario, v.precio_venta_sugerido
       FROM public.recetas r
       LEFT JOIN public.asignaturas a ON r.asignatura_id = a.asignatura_id
       LEFT JOIN public.usuarios u ON r.usuario_creador_id = u.usuario_id
       LEFT JOIN LATERAL (
            SELECT * FROM public.recetas_versiones rv
            WHERE rv.receta_id = r.receta_id
            ORDER BY rv.version_id DESC
            LIMIT 1
       ) v ON true
       ORDER BY r.receta_id DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("🔴 Error al obtener recetas:", error);
    res.status(500).json({ error: "Error al obtener las recetas." });
  }
}

/* ============================================================
   3. GET /api/recetas/:id
   Detalle completo: receta + todas sus versiones + insumos
   de la última versión. Si el que consulta es
   Estudiante (rol 3), valida que tenga acceso asignado.
   ============================================================ */
/* ============================================================
   Helper compartido: trae el detalle completo de una receta
   (ficha + última versión + insumos). Lo usan tanto
   obtenerRecetaPorId (JSON para la app) como exportarRecetaPdf
   (ficha técnica en PDF) para no duplicar las mismas 4 consultas.
   ============================================================ */
async function obtenerDetalleRecetaCompleto(id, { soloAprobadas = false } = {}) {
  const recetaResult = await pool.query(
    `SELECT r.*, a.nombre_asignatura, a.titulacion_id
     FROM public.recetas r
     LEFT JOIN public.asignaturas a ON r.asignatura_id = a.asignatura_id
     WHERE r.receta_id = $1`,
    [id]
  );

  if (recetaResult.rows.length === 0) {
    return null;
  }
  const receta = recetaResult.rows[0];

  const versionesResult = await pool.query(
    `SELECT * FROM public.recetas_versiones
     WHERE receta_id = $1 ${soloAprobadas ? "AND estado = 'APROBADA'" : ""}
     ORDER BY version_id DESC`,
    [id]
  );
  // Defensa: si la columna contenido_json quedó guardada como texto plano
  // (en vez de tipo json/jsonb reconocido por el driver), se parsea aquí
  // para que siempre se trabaje con un objeto { pasos: [...] } y no un
  // string en el que "pasos" no existe.
  const versiones = versionesResult.rows.map((v) => {
    if (typeof v.contenido_json === "string") {
      try {
        v.contenido_json = JSON.parse(v.contenido_json);
      } catch (e) {
        console.error("🔴 contenido_json no es JSON válido para version_id", v.version_id, e);
        v.contenido_json = null;
      }
    }
    return v;
  });
  const ultimaVersion = versiones[0] || null;

  let insumos = [];

  if (ultimaVersion) {
    const insumosResult = await pool.query(
      `SELECT rvi.insumo_id, ic.nombre_insumo, ic.unidad_medida,
              rvi.cantidad, ic.costo_unitario,
              (rvi.cantidad * ic.costo_unitario) AS subtotal
       FROM public.receta_version_insumos rvi
       JOIN public.insumos_costos ic ON rvi.insumo_id = ic.insumo_id
       WHERE rvi.version_id = $1`,
      [ultimaVersion.version_id]
    );
    insumos = insumosResult.rows;
  }

  return { receta, versiones, ultimaVersion, insumos };
}

async function obtenerRecetaPorId(req, res) {
  const { id } = req.params;

  try {
    if (req.user.rol === 3) {
      const acceso = await pool.query(
        `SELECT 1 FROM public.estudiante_receta_acceso
         WHERE estudiante_id = $1 AND receta_id = $2`,
        [req.user.id, id]
      );
      if (acceso.rows.length === 0) {
        return res.status(403).json({ error: "No tienes acceso a esta receta." });
      }
    }

    // El estudiante solo ve versiones APROBADAS (nunca borradores del docente)
    const detalle = await obtenerDetalleRecetaCompleto(id, { soloAprobadas: req.user.rol === 3 });
    if (!detalle) {
      return res.status(404).json({ error: "Receta no encontrada." });
    }
    if (req.user.rol === 3 && !detalle.ultimaVersion) {
      return res.status(404).json({ error: "Esta receta aún no tiene una versión aprobada." });
    }

    res.json({
      receta: detalle.receta,
      versiones: detalle.versiones,
      ultima_version: detalle.ultimaVersion,
      insumos: detalle.insumos
    });
  } catch (error) {
    console.error("🔴 Error al obtener receta:", error);
    res.status(500).json({ error: "Error interno al obtener la receta." });
  }
}

/* ============================================================
   4. PUT /api/recetas/:id
   Actualiza los datos básicos de la ficha maestra
   ============================================================ */
async function actualizarReceta(req, res) {
  const { id } = req.params;
  const { nombre, porciones, tiempo_prep_min, asignatura_id } = req.body;

  if (!enteroPositivo(id)) {
    return res.status(400).json({ error: "id de receta inválido." });
  }
  const errorCampos = validarCamposReceta({ nombre, porciones, tiempo_prep_min });
  if (errorCampos) {
    return res.status(400).json({ error: errorCampos });
  }

  try {
    const propiedad = await verificarPropiedadReceta(req, id);
    if (!propiedad.ok) return res.status(propiedad.status).json({ error: propiedad.error });

    const conflicto = await validarAsignaturaYDuplicado({
      nombre, asignatura_id, excluirRecetaId: Number(id)
    });
    if (conflicto) {
      return res.status(conflicto.status).json({ error: conflicto.error });
    }

    const result = await pool.query(
      `UPDATE public.recetas
       SET nombre = $1,
           porciones = $2,
           tiempo_prep_min = $3,
           asignatura_id = $4
       WHERE receta_id = $5
       RETURNING *`,
      [String(nombre).trim(), porciones, tiempo_prep_min || null, asignatura_id || null, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Receta no encontrada." });
    }

    res.json({ message: "Receta actualizada correctamente.", receta: result.rows[0] });
  } catch (error) {
    console.error("🔴 Error al actualizar receta:", error);
    res.status(500).json({ error: "Error interno al actualizar la receta." });
  }
}

/* ============================================================
   5. DELETE /api/recetas/:id
   Elimina la receta y todo lo que depende de ella
   ============================================================ */
async function eliminarReceta(req, res) {
  const { id } = req.params;

  try {
    const propiedad = await verificarPropiedadReceta(req, id);
    if (!propiedad.ok) return res.status(propiedad.status).json({ error: propiedad.error });

    const eliminado = await conTransaccion(async (client) => {
      const versiones = await client.query(
        `SELECT version_id FROM public.recetas_versiones WHERE receta_id = $1`,
        [id]
      );
      const versionIds = versiones.rows.map((v) => v.version_id);

      if (versionIds.length > 0) {
        await client.query(
          `DELETE FROM public.receta_version_insumos WHERE version_id = ANY($1)`,
          [versionIds]
        );
        // Limpieza de datos antiguos: la FK de receta_articulos_menaje es NO ACTION (sin cascada),
        // así que si una versión aún tiene filas de menaje, borrar la versión fallaría.
        // El menaje ya no se crea ni se muestra; la tabla no se modifica.
        await client.query(
          `DELETE FROM public.receta_articulos_menaje WHERE version_id = ANY($1)`,
          [versionIds]
        );
      }

      await client.query(`DELETE FROM public.recetas_versiones WHERE receta_id = $1`, [id]);
      await client.query(
        `DELETE FROM public.estudiante_receta_acceso WHERE receta_id = $1`,
        [id]
      );

      const recetaResult = await client.query(
        `DELETE FROM public.recetas WHERE receta_id = $1 RETURNING *`,
        [id]
      );
      return recetaResult.rows[0];
    });

    if (!eliminado) {
      return res.status(404).json({ error: "Receta no encontrada." });
    }

    res.json({ message: "Receta eliminada correctamente.", receta: eliminado });
  } catch (error) {
    console.error("🔴 Error al eliminar receta:", error);
    res.status(500).json({ error: "Error interno al eliminar la receta." });
  }
}

/* ============================================================
   6. POST /api/recetas/:id/versiones
   Crea una nueva versión de una receta existente
   ============================================================ */
async function crearVersion(req, res) {
  const { id } = req.params;
  const { numero_version, contenido_json, precio_venta_sugerido, insumos } = req.body;

  if (!enteroPositivo(id)) {
    return res.status(400).json({ error: "id de receta inválido." });
  }
  if (!numero_version) {
    return res.status(400).json({ error: "numero_version es obligatorio (ej: '1.1')." });
  }
  if (!/^\d{1,3}(\.\d{1,3})?$/.test(String(numero_version).trim())) {
    return res.status(400).json({ error: "numero_version debe tener formato numérico, por ejemplo '1.1'." });
  }
  const errorPrecio = validarPrecio(precio_venta_sugerido);
  if (errorPrecio) {
    return res.status(400).json({ error: errorPrecio });
  }

  try {
    const propiedad = await verificarPropiedadReceta(req, id);
    if (!propiedad.ok) return res.status(propiedad.status).json({ error: propiedad.error });

    const errorInsumos = await validarInsumosReceta(insumos);
    if (errorInsumos) {
      return res.status(400).json({ error: errorInsumos });
    }

    const resultado = await conTransaccion(async (client) => {
      const versionResult = await client.query(
        `INSERT INTO public.recetas_versiones
            (receta_id, numero_version, contenido_json, precio_venta_sugerido, estado)
         VALUES ($1, $2, $3, $4, 'BORRADOR')
         RETURNING *`,
        [id, numero_version, contenido_json || null, precio_venta_sugerido || 0]
      );
      let version = versionResult.rows[0];

      if (Array.isArray(insumos)) {
        for (const item of insumos) {
          // La columna "cantidad" es NUMERIC NOT NULL en receta_version_insumos
          // (no existe columna es_al_gusto en la BD real). Un ingrediente marcado
          // como "al gusto / c/n" (ej. canela, aceite para freír) se guarda como
          // cantidad = 0: el trigger de costo lo trata como $0 de aporte, y el
          // frontend interpreta cantidad === 0 como "al gusto" al mostrarlo.
          const cantidadFinal = item.es_al_gusto ? 0 : item.cantidad;
          await client.query(
            `INSERT INTO public.receta_version_insumos (version_id, insumo_id, cantidad)
             VALUES ($1, $2, $3)`,
            [version.version_id, item.insumo_id, cantidadFinal]
          );
        }
      }

      const versionActualizada = await client.query(
        `SELECT * FROM public.recetas_versiones WHERE version_id = $1`,
        [version.version_id]
      );
      return versionActualizada.rows[0];
    });

    res.status(201).json({ message: "Nueva versión creada.", version: resultado });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Ya existe esa versión para esta receta." });
    }
    console.error("🔴 Error al crear versión:", error);
    res.status(500).json({ error: "Error interno al crear la versión." });
  }
}

/* ============================================================
   7. PUT /api/recetas/versiones/:version_id/aprobar
   ============================================================ */
async function aprobarVersion(req, res) {
  const { version_id } = req.params;

  if (!/^\d+$/.test(String(version_id))) {
    return res.status(400).json({ error: "version_id inválido." });
  }

  // Error controlado: lleva el código HTTP que debe devolverse
  const falla = (httpStatus, mensaje) => Object.assign(new Error(mensaje), { httpStatus });

  try {
    const resultado = await conTransaccion(async (client) => {
      // FOR UPDATE: dos aprobaciones simultáneas de la misma versión no pueden pisarse
      const v = await client.query(
        `SELECT rv.version_id, rv.receta_id, rv.estado, rv.numero_version, r.usuario_creador_id
           FROM public.recetas_versiones rv
           JOIN public.recetas r ON r.receta_id = rv.receta_id
          WHERE rv.version_id = $1
          FOR UPDATE OF rv`,
        [version_id]
      );
      if (v.rows.length === 0) throw falla(404, "Versión no encontrada.");
      const version = v.rows[0];

      // Un Docente solo aprueba versiones de sus propias recetas; el Admin, cualquiera
      if (req.user.rol === 2 && String(version.usuario_creador_id) !== String(req.user.id)) {
        throw falla(403, "Solo puedes aprobar versiones de las recetas que tú creaste.");
      }

      if (version.estado === "APROBADA") {
        throw falla(409, `La versión ${version.numero_version} ya está aprobada.`);
      }
      if (version.estado !== "BORRADOR") {
        throw falla(409, `Solo se pueden aprobar versiones en borrador (estado actual: ${version.estado}).`);
      }

      // No se publica una versión vacía: debe tener al menos un ingrediente
      const ingredientes = await client.query(
        `SELECT COUNT(*)::int AS total FROM public.receta_version_insumos WHERE version_id = $1`,
        [version_id]
      );
      if (ingredientes.rows[0].total === 0) {
        throw falla(400, "La versión no tiene ingredientes. Agrega al menos uno antes de aprobarla.");
      }

      // Evita que una versión antigua desplace a una más reciente ya aprobada
      const masReciente = await client.query(
        `SELECT numero_version FROM public.recetas_versiones
          WHERE receta_id = $1 AND estado = 'APROBADA' AND version_id > $2
          LIMIT 1`,
        [version.receta_id, version_id]
      );
      if (masReciente.rows.length > 0) {
        throw falla(409, `Ya existe una versión aprobada más reciente (${masReciente.rows[0].numero_version}).`);
      }

      // La versión aprobada anterior de esta receta queda como REEMPLAZADA (historial claro)
      const reemplazadas = await client.query(
        `UPDATE public.recetas_versiones
            SET estado = 'REEMPLAZADA'
          WHERE receta_id = $1 AND estado = 'APROBADA' AND version_id <> $2`,
        [version.receta_id, version_id]
      );

      const aprobada = await client.query(
        `UPDATE public.recetas_versiones
            SET estado = 'APROBADA'
          WHERE version_id = $1
          RETURNING *`,
        [version_id]
      );

      return { version: aprobada.rows[0], reemplazadas: reemplazadas.rowCount };
    });

    res.json({
      message: resultado.reemplazadas > 0
        ? "Versión aprobada. La versión aprobada anterior quedó como reemplazada."
        : "Versión aprobada.",
      version: resultado.version
    });
  } catch (error) {
    if (error.httpStatus) {
      return res.status(error.httpStatus).json({ error: error.message });
    }
    console.error("🔴 Error al aprobar versión:", error);
    res.status(500).json({ error: "Error interno al aprobar la versión." });
  }
}

/* ============================================================
   8. POST /api/recetas/:id/asignar
   Asigna (da acceso a) una receta a un estudiante
   ============================================================ */
async function asignarReceta(req, res) {
  const { id } = req.params;
  const { estudiante_id } = req.body;

  if (!estudiante_id) {
    return res.status(400).json({ error: "estudiante_id es obligatorio." });
  }

  try {
    const rec = await pool.query(`SELECT 1 FROM public.recetas WHERE receta_id = $1`, [id]);
    if (rec.rows.length === 0) {
      return res.status(404).json({ error: "Receta no encontrada." });
    }
    const est = await pool.query(
      `SELECT 1 FROM public.estudiantes WHERE estudiante_id = $1`, [String(estudiante_id)]
    );
    if (est.rows.length === 0) {
      return res.status(404).json({ error: "El estudiante no existe." });
    }

    const result = await pool.query(
      `INSERT INTO public.estudiante_receta_acceso (estudiante_id, receta_id)
       VALUES ($1, $2)
       ON CONFLICT (estudiante_id, receta_id) DO NOTHING
       RETURNING *`,
      [estudiante_id, id]
    );

    res.status(201).json({
      message:
        result.rows.length > 0
          ? "Receta asignada al estudiante correctamente."
          : "El estudiante ya tenía acceso a esta receta.",
      acceso: result.rows[0] || null,
    });
  } catch (error) {
    console.error("🔴 Error al asignar receta:", error);
    res.status(500).json({ error: "Error interno al asignar la receta." });
  }
}

/* ============================================================
   9. GET /api/recetas/mis-recetas
   Recetas asignadas al estudiante autenticado
   ============================================================ */
async function misRecetas(req, res) {
  try {
    const estudiante_id = req.user.id;

    const result = await pool.query(
      `SELECT
          r.receta_id, r.nombre, r.porciones, r.tiempo_prep_min,
          a.nombre_asignatura,
          v.numero_version, v.estado AS estado_version,
          v.costo_unitario, v.precio_venta_sugerido,
          era.fecha_acceso
       FROM public.estudiante_receta_acceso era
       JOIN public.recetas r ON era.receta_id = r.receta_id
       LEFT JOIN public.asignaturas a ON r.asignatura_id = a.asignatura_id
       LEFT JOIN LATERAL (
            SELECT * FROM public.recetas_versiones rv
            WHERE rv.receta_id = r.receta_id AND rv.estado = 'APROBADA'
            ORDER BY rv.version_id DESC
            LIMIT 1
       ) v ON true
       WHERE era.estudiante_id = $1
       ORDER BY era.fecha_acceso DESC`,
      [estudiante_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("🔴 Error al obtener mis recetas:", error);
    res.status(500).json({ error: "Error al obtener tus recetas asignadas." });
  }
}

/* ============================================================
   GET /api/recetas/:id/exportar/pdf
   Genera la ficha técnica de la receta en PDF, formato fijo,
   igual patrón que el módulo de Reportes: se arma 100% en el
   backend y se manda como archivo descargable.
   ============================================================ */
async function exportarRecetaPdf(req, res) {
  const { id } = req.params;

  try {
    if (req.user.rol === 3) {
      const acceso = await pool.query(
        `SELECT 1 FROM public.estudiante_receta_acceso
         WHERE estudiante_id = $1 AND receta_id = $2`,
        [req.user.id, id]
      );
      if (acceso.rows.length === 0) {
        return res.status(403).json({ error: "No tienes acceso a esta receta." });
      }
    }

    // El estudiante solo ve versiones APROBADAS (nunca borradores del docente)
    const detalle = await obtenerDetalleRecetaCompleto(id, { soloAprobadas: req.user.rol === 3 });
    if (!detalle) {
      return res.status(404).json({ error: "Receta no encontrada." });
    }
    if (req.user.rol === 3 && !detalle.ultimaVersion) {
      return res.status(404).json({ error: "Esta receta aún no tiene una versión aprobada." });
    }
    const { receta, ultimaVersion, insumos } = detalle;
    const pasos = ultimaVersion?.contenido_json?.pasos || [];

    const doc = new PDFDocument({ margin: 45, size: "A4" });
    const nombreArchivo = `receta-${receta.nombre.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.pdf`;

    res.setHeader("Content-Disposition", `attachment; filename="${nombreArchivo}"`);
    res.setHeader("Content-Type", "application/pdf");
    doc.pipe(res);

    // ── Encabezado ──────────────────────────────────────────
    doc.fillColor("#1a1a1a").font("Helvetica-Bold").fontSize(18).text("NOVA CUISINE");
    doc.fillColor("#b8860b").font("Helvetica-Bold").fontSize(10).text("FICHA TÉCNICA DE RECETA");
    doc.moveDown(0.6);
    doc.moveTo(45, doc.y).lineTo(doc.page.width - 45, doc.y).strokeColor("#b8860b").lineWidth(1.5).stroke();
    doc.moveDown(0.8);

    // ── Título y datos generales ────────────────────────────
    doc.fillColor("#1a1a1a").font("Helvetica-Bold").fontSize(20).text(receta.nombre);
    doc.moveDown(0.3);

    doc.font("Helvetica").fontSize(9).fillColor("#555555");
    const meta = [
      receta.nombre_asignatura ? `Asignatura: ${receta.nombre_asignatura}` : null,
      `Porciones: ${receta.porciones || "-"}`,
      `Tiempo de preparación: ${receta.tiempo_prep_min ? receta.tiempo_prep_min + " min" : "-"}`,
      ultimaVersion ? `Versión: ${ultimaVersion.numero_version} (${ultimaVersion.estado})` : null,
    ].filter(Boolean).join("   ·   ");
    doc.text(meta);
    doc.moveDown(1);

    // ── Ingredientes ─────────────────────────────────────────
    doc.fillColor("#1a1a1a").font("Helvetica-Bold").fontSize(12).text("Ingredientes");
    doc.moveDown(0.3);
    doc.font("Helvetica").fontSize(9.5);

    if (insumos.length > 0) {
      insumos.forEach((ins) => {
        const cantidadTexto = Number(ins.cantidad) > 0
          ? `${Number(ins.cantidad)} ${ins.unidad_medida}`
          : "Al gusto / c/n";
        doc.fillColor("#1a1a1a").text(`•  ${cantidadTexto}  —  ${ins.nombre_insumo}`);
      });
    } else {
      doc.fillColor("#999999").text("Esta receta aún no tiene ingredientes registrados.");
    }
    doc.moveDown(1);

    // ── Pasos de preparación ────────────────────────────────
    doc.fillColor("#1a1a1a").font("Helvetica-Bold").fontSize(12).text("Pasos de Preparación");
    doc.moveDown(0.3);
    doc.font("Helvetica").fontSize(9.5);

    if (pasos.length > 0) {
      const xNumero = doc.page.margins.left;
      const xTexto = doc.page.margins.left + 24;
      const anchoTexto = doc.page.width - xTexto - doc.page.margins.right;

      pasos.forEach((paso, i) => {
        const numero = `${i + 1}.`;

        // Salto de página manual si el paso no cabe en lo que queda de hoja
        const alturaEstimada = doc.heightOfString(paso, { width: anchoTexto });
        if (doc.y + alturaEstimada > doc.page.height - doc.page.margins.bottom) {
          doc.addPage();
        }

        const yInicio = doc.y;
        doc.fillColor("#b8860b").font("Helvetica-Bold").text(numero, xNumero, yInicio, { width: 20 });
        doc.fillColor("#1a1a1a").font("Helvetica").text(paso, xTexto, yInicio, { width: anchoTexto });
        doc.moveDown(0.6);
      });
    } else {
      doc.fillColor("#999999").text("Aún no se han registrado los pasos de preparación de esta receta.");
    }

    // ── Pie de página ────────────────────────────────────────
    doc.moveDown(1);
    doc.fontSize(7.5).fillColor("#aaaaaa")
      .text(`Generado desde Nova Cuisine el ${new Date().toLocaleString("es-EC")}`, { align: "center" });

    doc.end();
  } catch (error) {
    console.error("🔴 Error al exportar receta a PDF:", error);
    if (!res.headersSent) {
      res.status(500).json({ error: "Error al generar el PDF de la receta." });
    } else {
      res.end();
    }
  }
}

module.exports = {
  crearReceta,
  obtenerRecetas,
  obtenerRecetaPorId,
  actualizarReceta,
  eliminarReceta,
  crearVersion,
  aprobarVersion,
  asignarReceta,
  misRecetas,
  exportarRecetaPdf,
};
