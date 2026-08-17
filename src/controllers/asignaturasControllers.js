// src/controllers/asignaturasControllers.js
const pool = require("../db");

async function obtenerAsignaturas(req, res) {
  try {
    const result = await pool.query(
      `SELECT asignatura_id, nombre_asignatura, titulacion_id
       FROM public.asignaturas
       ORDER BY nombre_asignatura ASC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("🔴 Error al obtener asignaturas:", error);
    res.status(500).json({ error: "Error al obtener las asignaturas." });
  }
}

async function crearAsignatura(req, res) {
  const { nombre_asignatura, titulacion_id } = req.body;

  if (!nombre_asignatura) {
    return res.status(400).json({ error: "nombre_asignatura es obligatorio." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO public.asignaturas (nombre_asignatura, titulacion_id)
       VALUES ($1, $2) RETURNING *`,
      [nombre_asignatura, titulacion_id || null]
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

module.exports = { obtenerAsignaturas, crearAsignatura };
