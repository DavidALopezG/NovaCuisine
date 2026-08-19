// src/controllers/recetasControllers.js
const pool = require("../db");

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

/* ============================================================
   1. POST /api/recetas
   Crea la ficha maestra + su primera versión (1.0, BORRADOR)
   body: { nombre, porciones, tiempo_prep_min, asignatura_id,
           contenido_json, precio_venta_sugerido,
           insumos: [{insumo_id, cantidad}],
           menaje: [{articulo_id, cantidad_requerida}] }
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
    menaje,
  } = req.body;

  if (!nombre || !porciones) {
    return res.status(400).json({ error: "nombre y porciones son obligatorios." });
  }

  try {
    const usuario_creador_id = req.user.id;

    const resultado = await conTransaccion(async (client) => {
      const recetaResult = await client.query(
        `INSERT INTO public.recetas
            (nombre, porciones, tiempo_prep_min, asignatura_id, usuario_creador_id)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [nombre, porciones, tiempo_prep_min || null, asignatura_id || null, usuario_creador_id]
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

      if (Array.isArray(menaje)) {
        for (const item of menaje) {
          await client.query(
            `INSERT INTO public.receta_articulos_menaje (version_id, articulo_id, cantidad_requerida)
             VALUES ($1, $2, $3)`,
            [version.version_id, item.articulo_id, item.cantidad_requerida]
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
          a.asignatura_id, a.nombre_asignatura,
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
   y menaje de la última versión. Si el que consulta es
   Estudiante (rol 3), valida que tenga acceso asignado.
   ============================================================ */
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

    const recetaResult = await pool.query(
      `SELECT r.*, a.nombre_asignatura
       FROM public.recetas r
       LEFT JOIN public.asignaturas a ON r.asignatura_id = a.asignatura_id
       WHERE r.receta_id = $1`,
      [id]
    );

    if (recetaResult.rows.length === 0) {
      return res.status(404).json({ error: "Receta no encontrada." });
    }
    const receta = recetaResult.rows[0];

    const versionesResult = await pool.query(
      `SELECT * FROM public.recetas_versiones
       WHERE receta_id = $1
       ORDER BY version_id DESC`,
      [id]
    );
    const versiones = versionesResult.rows;
    const ultimaVersion = versiones[0] || null;

    let insumos = [];
    let menaje = [];

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

      const menajeResult = await pool.query(
        `SELECT ram.articulo_id, ia.nombre, ia.tipo, ram.cantidad_requerida
         FROM public.receta_articulos_menaje ram
         JOIN public.inventario_articulos ia ON ram.articulo_id = ia.articulo_id
         WHERE ram.version_id = $1`,
        [ultimaVersion.version_id]
      );
      menaje = menajeResult.rows;
    }

    res.json({ receta, versiones, ultima_version: ultimaVersion, insumos, menaje });
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

  try {
    const result = await pool.query(
      `UPDATE public.recetas
       SET nombre = $1,
           porciones = $2,
           tiempo_prep_min = $3,
           asignatura_id = $4
       WHERE receta_id = $5
       RETURNING *`,
      [nombre, porciones, tiempo_prep_min || null, asignatura_id || null, id]
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
  const { numero_version, contenido_json, precio_venta_sugerido, insumos, menaje } = req.body;

  if (!numero_version) {
    return res.status(400).json({ error: "numero_version es obligatorio (ej: '1.1')." });
  }

  try {
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

      if (Array.isArray(menaje)) {
        for (const item of menaje) {
          await client.query(
            `INSERT INTO public.receta_articulos_menaje (version_id, articulo_id, cantidad_requerida)
             VALUES ($1, $2, $3)`,
            [version.version_id, item.articulo_id, item.cantidad_requerida]
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

  try {
    const result = await pool.query(
      `UPDATE public.recetas_versiones
       SET estado = 'APROBADA'
       WHERE version_id = $1
       RETURNING *`,
      [version_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Versión no encontrada." });
    }

    res.json({ message: "Versión aprobada.", version: result.rows[0] });
  } catch (error) {
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
};
