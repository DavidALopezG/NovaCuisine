// src/controllers/titulacionesControllers.js
const pool = require("../db");

/** Valida nombre y duración. Devuelve { error } o { nombre, tipo, duracion }. */
const TIPOS_VALIDOS = ["Titulación", "Certificación"];

function validarTitulacion({ nombre_titulacion, tipo, duracion_meses }) {
    const nombre = String(nombre_titulacion || "").trim();
    if (nombre.length < 3 || nombre.length > 120) {
        return { error: "El nombre de la titulación debe tener entre 3 y 120 caracteres." };
    }
    if (!tipo || !TIPOS_VALIDOS.includes(tipo)) {
        return { error: `tipo debe ser uno de: ${TIPOS_VALIDOS.join(", ")}.` };
    }
    let duracion = null;
    if (duracion_meses !== null && duracion_meses !== undefined && duracion_meses !== "") {
        duracion = Number(duracion_meses);
        if (!Number.isInteger(duracion) || duracion < 1 || duracion > 120) {
            return { error: "duracion_meses debe ser un número entero entre 1 y 120." };
        }
    }
    return { nombre, tipo: tipo || null, duracion };
}

async function obtenerTitulaciones(req, res) {
    try {
        const result = await pool.query(
            `SELECT titulacion_id, nombre_titulacion, tipo, duracion_meses
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
    const v = validarTitulacion(req.body);
    if (v.error) {
        return res.status(400).json({ error: v.error });
    }

    try {
        const dup = await pool.query(
            `SELECT 1 FROM public.titulaciones WHERE LOWER(TRIM(nombre_titulacion)) = LOWER($1)`, [v.nombre]
        );
        if (dup.rows.length > 0) {
            return res.status(409).json({ error: "Esa titulación ya existe." });
        }

        const result = await pool.query(
            `INSERT INTO public.titulaciones (nombre_titulacion, tipo, duracion_meses)
             VALUES ($1, $2, $3) RETURNING *`,
            [v.nombre, v.tipo, v.duracion]
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
    const v = validarTitulacion(req.body);
    if (v.error) {
        return res.status(400).json({ error: v.error });
    }

    try {
        const dup = await pool.query(
            `SELECT 1 FROM public.titulaciones
             WHERE LOWER(TRIM(nombre_titulacion)) = LOWER($1) AND titulacion_id <> $2`,
            [v.nombre, id]
        );
        if (dup.rows.length > 0) {
            return res.status(409).json({ error: "Ya existe otra titulación con ese nombre." });
        }

        const result = await pool.query(
            `UPDATE public.titulaciones
                SET nombre_titulacion = $1,
                    tipo = $2,
                    duracion_meses = $3
              WHERE titulacion_id = $4 RETURNING *`,
            [v.nombre, v.tipo, v.duracion, id]
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
