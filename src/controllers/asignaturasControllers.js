// src/controllers/asignaturasControllers.js
const pool = require("../db");

const NIVELES_VALIDOS = ["Iniciación", "Profesionalización", "Especialización"];

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

  if (!nombre_asignatura) {
    return res.status(400).json({ error: "nombre_asignatura es obligatorio." });
  }

  if (nivel && !NIVELES_VALIDOS.includes(nivel)) {
    return res.status(400).json({ error: `nivel debe ser uno de: ${NIVELES_VALIDOS.join(", ")}.` });
  }

  try {
    const result = await pool.query(
      `INSERT INTO public.asignaturas (nombre_asignatura, titulacion_id, nivel, es_electiva)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [nombre_asignatura, titulacion_id || null, nivel || null, !!es_electiva]
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

  if (!nombre_asignatura) {
    return res.status(400).json({ error: "nombre_asignatura es obligatorio." });
  }

  if (nivel && !NIVELES_VALIDOS.includes(nivel)) {
    return res.status(400).json({ error: `nivel debe ser uno de: ${NIVELES_VALIDOS.join(", ")}.` });
  }

  try {
    const result = await pool.query(
      `UPDATE public.asignaturas
          SET nombre_asignatura = $1,
              titulacion_id = $2,
              nivel = $3,
              es_electiva = $4
        WHERE asignatura_id = $5 RETURNING *`,
      [nombre_asignatura, titulacion_id || null, nivel || null, !!es_electiva, id]
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
