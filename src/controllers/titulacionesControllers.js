// src/controllers/titulacionesControllers.js
const pool = require("../db");

async function obtenerTitulaciones(req, res) {
    try {
        const result = await pool.query(
            `SELECT titulacion_id, nombre_titulacion
             FROM public.titulaciones
             ORDER BY nombre_titulacion ASC`
        );
        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener titulaciones:", error);
        res.status(500).json({ error: "Error al obtener las titulaciones." });
    }
}

async function crearTitulacion(req, res) {
    const { nombre_titulacion } = req.body;

    if (!nombre_titulacion) {
        return res.status(400).json({ error: "nombre_titulacion es obligatorio." });
    }

    try {
        const result = await pool.query(
            `INSERT INTO public.titulaciones (nombre_titulacion)
             VALUES ($1) RETURNING *`,
            [nombre_titulacion]
        );
        res.status(201).json({ message: "Titulación creada.", titulacion: result.rows[0] });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ error: "Esa titulación ya existe." });
        }
        console.error("🔴 Error al crear titulación:", error);
        res.status(500).json({ error: "Error interno al crear la titulación." });
    }
}

async function actualizarTitulacion(req, res) {
    const { id } = req.params;
    const { nombre_titulacion } = req.body;

    try {
        const result = await pool.query(
            `UPDATE public.titulaciones SET nombre_titulacion = $1
             WHERE titulacion_id = $2 RETURNING *`,
            [nombre_titulacion, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Titulación no encontrada." });
        }

        res.json({ message: "Titulación actualizada.", titulacion: result.rows[0] });
    } catch (error) {
        console.error("🔴 Error al actualizar titulación:", error);
        res.status(500).json({ error: "Error interno al actualizar la titulación." });
    }
}

async function eliminarTitulacion(req, res) {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `DELETE FROM public.titulaciones WHERE titulacion_id = $1 RETURNING *`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Titulación no encontrada." });
        }

        res.json({ message: "Titulación eliminada.", titulacion: result.rows[0] });
    } catch (error) {
        if (error.code === "23503") {
            return res.status(409).json({
                error: "No se puede eliminar: hay asignaturas o estudiantes vinculados a esta titulación."
            });
        }
        console.error("🔴 Error al eliminar titulación:", error);
        res.status(500).json({ error: "Error interno al eliminar la titulación." });
    }
}

module.exports = {
    obtenerTitulaciones,
    crearTitulacion,
    actualizarTitulacion,
    eliminarTitulacion
};
