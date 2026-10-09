// src/controllers/asignaturasControllers.js
const pool = require("../db");

const NIVELES_VALIDOS = ["Iniciación", "Profesionalización", "Especialización"];

/** Valida el cuerpo de crear/editar asignatura. Devuelve mensaje de error o null. */
async function validarAsignatura({ nombre_asignatura, titulacion_id, nivel, es_electiva }) {
  const nombre = String(nombre_asignatura || "").trim();
  if (nombre.length < 3 || nombre.length > 120) {
    return "El nombre de la asignatura debe tener entre 3 y 120 caracteres.";
  }
  if (!titulacion_id) {
    return "Selecciona la titulación a la que pertenece la asignatura.";
  }
  if (!nivel) {
    return "Selecciona el nivel del pensum.";
  }
  if (!NIVELES_VALIDOS.includes(nivel)) {
    return `nivel debe ser uno de: ${NIVELES_VALIDOS.join(", ")}.`;
  }
  const t = await pool.query(`SELECT 1 FROM public.titulaciones WHERE titulacion_id = $1`, [titulacion_id]);
  if (t.rows.length === 0) {
    return "La titulación seleccionada no existe.";
  }
  return null;
}

async function obtenerAsignaturas(req, res) {
  try {
    const result = await pool.query(
      `SELECT asignatura_id, nombre_asignatura, titulacion_id, nivel, es_electiva
       FROM public.asignaturas
       ORDER BY
         CASE nivel
           WHEN 'Iniciación' THEN 1
           WHEN 'Profesionalización' THEN 2
           WHEN 'Especialización' THEN 3
           ELSE 4
         END,
         nombre_asignatura ASC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("🔴 Error al obtener asignaturas:", error);
    res.status(500).json({ error: "Error al obtener las asignaturas." });
  }
}

async function crearAsignatura(req, res) {
  const { nombre_asignatura, titulacion_id, nivel, es_electiva } = req.body;

  try {
    const errorDatos = await validarAsignatura({ nombre_asignatura, titulacion_id, nivel, es_electiva });
    if (errorDatos) {
      return res.status(400).json({ error: errorDatos });
    }

    // Duplicado por nombre dentro de la misma titulación (sin distinguir mayúsculas)
    const dup = await pool.query(
      `SELECT 1 FROM public.asignaturas
       WHERE LOWER(TRIM(nombre_asignatura)) = LOWER(TRIM($1)) AND titulacion_id = $2`,
      [nombre_asignatura, titulacion_id]
    );
    if (dup.rows.length > 0) {
      return res.status(409).json({ error: "Ya existe una asignatura con ese nombre en esa titulación." });
    }

    const result = await pool.query(
      `INSERT INTO public.asignaturas (nombre_asignatura, titulacion_id, nivel, es_electiva)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [String(nombre_asignatura).trim(), titulacion_id, nivel, !!es_electiva]
    );
    res.status(201).json({ message: "Asignatura creada.", asignatura: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Esa asignatura ya existe." });
    }
    console.error("🔴 Error al crear asignatura:", error);
    res.status(500).json({ error: "Error interno al crear la asignatura." });
  }
}

async function actualizarAsignatura(req, res) {
  const { id } = req.params;
  const { nombre_asignatura, titulacion_id, nivel, es_electiva } = req.body;

  try {
    const errorDatos = await validarAsignatura({ nombre_asignatura, titulacion_id, nivel, es_electiva });
    if (errorDatos) {
      return res.status(400).json({ error: errorDatos });
    }

    // Si cambia de titulación, no debe tener grupos/horarios ya creados (quedarían inconsistentes)
    const previa = await pool.query(
      `SELECT titulacion_id FROM public.asignaturas WHERE asignatura_id = $1`, [id]
    );
    if (previa.rows.length === 0) {
      return res.status(404).json({ error: "Asignatura no encontrada." });
    }
    if (Number(previa.rows[0].titulacion_id) !== Number(titulacion_id)) {
      const h = await pool.query(
        `SELECT COUNT(*)::int AS total FROM public.horarios_clase WHERE asignatura_id = $1`, [id]
      );
      if (h.rows[0].total > 0) {
        return res.status(409).json({
          error: `No se puede cambiar la titulación: la asignatura ya tiene ${h.rows[0].total} grupo(s)/horario(s).`
        });
      }
    }

    const dup = await pool.query(
      `SELECT 1 FROM public.asignaturas
       WHERE LOWER(TRIM(nombre_asignatura)) = LOWER(TRIM($1)) AND titulacion_id = $2 AND asignatura_id <> $3`,
      [nombre_asignatura, titulacion_id, id]
    );
    if (dup.rows.length > 0) {
      return res.status(409).json({ error: "Ya existe otra asignatura con ese nombre en esa titulación." });
    }

    const result = await pool.query(
      `UPDATE public.asignaturas
          SET nombre_asignatura = $1,
              titulacion_id = $2,
              nivel = $3,
              es_electiva = $4
        WHERE asignatura_id = $5 RETURNING *`,
      [String(nombre_asignatura).trim(), titulacion_id, nivel, !!es_electiva, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Asignatura no encontrada." });
    }

    res.json({ message: "Asignatura actualizada.", asignatura: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Ya existe otra asignatura con ese nombre." });
    }
    console.error("🔴 Error al actualizar asignatura:", error);
    res.status(500).json({ error: "Error interno al actualizar la asignatura." });
  }
}

async function eliminarAsignatura(req, res) {
  const { id } = req.params;

  try {
    const result = await pool.query(
      `DELETE FROM public.asignaturas WHERE asignatura_id = $1 RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Asignatura no encontrada." });
    }

    res.json({ message: "Asignatura eliminada.", asignatura: result.rows[0] });
  } catch (error) {
    if (error.code === "23503") {
      return res.status(409).json({
        error: "No se puede eliminar: hay horarios/grupos o recetas vinculados a esta asignatura."
      });
    }
    console.error("🔴 Error al eliminar asignatura:", error);
    res.status(500).json({ error: "Error interno al eliminar la asignatura." });
  }
}

module.exports = {
  obtenerAsignaturas,
  crearAsignatura,
  actualizarAsignatura,
  eliminarAsignatura
};
