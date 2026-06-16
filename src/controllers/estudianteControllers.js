const pool = require("../db");

// 1. Crear Estudiante
async function crearEstudiante(req, res) {
    const { codigo_estudiante, nombre, apellido, email, titulacion_id } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO public.estudiantes
            (codigo_estudiante, nombre, apellido, email, titulacion_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [codigo_estudiante, nombre, apellido, email, titulacion_id]
        );

        res.status(201).json({
            message: "Estudiante creado correctamente.",
            estudiante: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al crear estudiante:", error);
        res.status(500).json({ error: "Error interno al crear estudiante." });
    }
}


// 2. Obtener todos los estudiantes
async function obtenerEstudiantes(req, res) {
    try {
        const result = await pool.query(
            `SELECT estudiante_id, codigo_estudiante, nombre, apellido, email, titulacion_id
             FROM public.estudiantes
             ORDER BY estudiante_id ASC`
        );

        res.json(result.rows);

    } catch (error) {
        console.error("🔴 Error al obtener estudiantes:", error);
        res.status(500).json({ error: "Error al obtener estudiantes." });
    }
}


// 3. Obtener estudiante por ID
async function obtenerEstudiantePorId(req, res) {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `SELECT * FROM public.estudiantes WHERE estudiante_id = $1`,
            [id]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: "Estudiante no encontrado." });

        res.json(result.rows[0]);

    } catch (error) {
        console.error("🔴 Error al obtener estudiante:", error);
        res.status(500).json({ error: "Error interno al obtener estudiante." });
    }
}


// 4. Actualizar Estudiante
async function actualizarEstudiante(req, res) {
    const { id } = req.params;
    const { codigo_estudiante, nombre, apellido, email, titulacion_id } = req.body;

    try {
        const result = await pool.query(
            `UPDATE public.estudiantes
             SET codigo_estudiante = $1,
                 nombre = $2,
                 apellido = $3,
                 email = $4,
                 titulacion_id = $5
             WHERE estudiante_id = $6
             RETURNING *`,
            [codigo_estudiante, nombre, apellido, email, titulacion_id, id]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: "Estudiante no encontrado." });

        res.json({
            message: "Estudiante actualizado correctamente.",
            estudiante: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al actualizar estudiante:", error);
        res.status(500).json({ error: "Error interno al actualizar estudiante." });
    }
}


// 5. Eliminar estudiante (borrado real o puedes cambiarlo a baja lógica)
async function eliminarEstudiante(req, res) {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `DELETE FROM public.estudiantes WHERE estudiante_id = $1 RETURNING *`,
            [id]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: "Estudiante no encontrado." });

        res.json({
            message: "Estudiante eliminado.",
            estudiante: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al eliminar estudiante:", error);
        res.status(500).json({ error: "Error interno al eliminar estudiante." });
    }
}

module.exports = {
    crearEstudiante,
    obtenerEstudiantes,
    obtenerEstudiantePorId,
    actualizarEstudiante,
    eliminarEstudiante
};
