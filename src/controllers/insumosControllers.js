// src/controllers/insumosControllers.js
const pool = require("../db");
const { textoEnRango, numeroEnRango } = require("../utils/validaciones");

const COSTO_MAXIMO = 100000;

/** Valida el cuerpo de crear insumo. Devuelve mensaje de error o null. */
function validarInsumo({ nombre_insumo, costo_unitario, unidad_medida }) {
  if (!textoEnRango(nombre_insumo, 2, 120)) {
    return "El nombre del insumo debe tener entre 2 y 120 caracteres.";
  }
  if (!textoEnRango(unidad_medida, 1, 30)) {
    return "La unidad de medida es obligatoria (máximo 30 caracteres).";
  }
  if (!numeroEnRango(costo_unitario, { min: 0, max: COSTO_MAXIMO })) {
    return `costo_unitario debe ser un número entre 0 y ${COSTO_MAXIMO}.`;
  }
  return null;
}

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

  const errorDatos = validarInsumo({ nombre_insumo, costo_unitario, unidad_medida });
  if (errorDatos) {
    return res.status(400).json({ error: errorDatos });
  }

  const nombre = String(nombre_insumo).trim();
  const unidad = String(unidad_medida).trim();

  try {
    // Duplicado por nombre (sin distinguir mayúsculas ni espacios sobrantes)
    const dup = await pool.query(
      `SELECT 1 FROM public.insumos_costos WHERE LOWER(TRIM(nombre_insumo)) = LOWER($1)`,
      [nombre]
    );
    if (dup.rows.length > 0) {
      return res.status(409).json({ error: "Ese insumo ya existe." });
    }

    const result = await pool.query(
      `INSERT INTO public.insumos_costos (nombre_insumo, costo_unitario, unidad_medida)
       VALUES ($1, $2, $3) RETURNING *`,
      [nombre, Number(costo_unitario), unidad]
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
