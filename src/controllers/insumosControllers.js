// src/controllers/insumosControllers.js
const pool = require("../db");

async function obtenerInsumos(req, res) {
  try {
    const result = await pool.query(
      `SELECT insumo_id, nombre_insumo, costo_unitario, unidad_medida
       FROM public.insumos_costos
       ORDER BY nombre_insumo ASC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error("🔴 Error al obtener insumos:", error);
    res.status(500).json({ error: "Error al obtener los insumos." });
  }
}

async function crearInsumo(req, res) {
  const { nombre_insumo, costo_unitario, unidad_medida } = req.body;

  if (!nombre_insumo || costo_unitario === undefined || !unidad_medida) {
    return res
      .status(400)
      .json({ error: "nombre_insumo, costo_unitario y unidad_medida son obligatorios." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO public.insumos_costos (nombre_insumo, costo_unitario, unidad_medida)
       VALUES ($1, $2, $3) RETURNING *`,
      [nombre_insumo, costo_unitario, unidad_medida]
    );
    res.status(201).json({ message: "Insumo creado.", insumo: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Ese insumo ya existe." });
    }
    console.error("🔴 Error al crear insumo:", error);
    res.status(500).json({ error: "Error interno al crear el insumo." });
  }
}

module.exports = { obtenerInsumos, crearInsumo };
