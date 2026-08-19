const pool = require("../db");

// 1. Crear Estudiante
async function crearEstudiante(req, res) {
    const { usuario_id, codigo_estudiante, nombre, apellido, email, titulacion_id } = req.body;

    // usuario_id es obligatorio: todo estudiante debe estar vinculado a un usuario
    if (!usuario_id || !nombre || !apellido || !email) {
        return res.status(400).json({
            error: "usuario_id, nombre, apellido y email son obligatorios. Usa el módulo de Usuarios para crear estudiantes."
        });
    }

    try {
        const codigo = codigo_estudiante || `EST-${Date.now().toString().slice(-5)}`;

        const result = await pool.query(
            `INSERT INTO public.estudiantes
            (estudiante_id, codigo_estudiante, nombre, apellido, email, titulacion_id, fecha_ingreso)
             VALUES ($1, $2, $3, $4, $5, $6, NOW())
             RETURNING *`,
            [usuario_id, codigo, nombre, apellido, email, titulacion_id || 1]
        );

        res.status(201).json({
            message: "Estudiante creado correctamente.",
            estudiante: result.rows[0]
        });

    } catch (error) {
        if (error.code === "23505") {
            if (error.detail && error.detail.toLowerCase().includes("email")) {
                return res.status(409).json({ error: "Ya existe un estudiante con ese correo electrónico." });
            }
            return res.status(409).json({ error: "Ya existe un estudiante con esa cédula / ID." });
        }
        if (error.code === "23503") {
            return res.status(400).json({ error: "El usuario_id no existe en la tabla de usuarios." });
        }
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
        // Verificar dependencias antes de eliminar
        const cobros = await pool.query(
            `SELECT COUNT(*) FROM public.cobros_obligaciones WHERE estudiante_id = $1`, [id]
        );
        const recetas = await pool.query(
            `SELECT COUNT(*) FROM public.estudiante_receta_acceso WHERE estudiante_id = $1`, [id]
        );

        const totalCobros  = parseInt(cobros.rows[0].count);
        const totalRecetas = parseInt(recetas.rows[0].count);

        if (totalCobros > 0 || totalRecetas > 0) {
            return res.status(409).json({
                error: `No se puede eliminar: el estudiante tiene ${totalCobros} cobro(s) y ${totalRecetas} receta(s) asignada(s). Desactiva su cuenta en lugar de eliminarla.`
            });
        }

        // Sin dependencias: proceder con el borrado
        const result = await pool.query(
            `DELETE FROM public.estudiantes WHERE estudiante_id = $1 RETURNING *`,
            [id]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: "Estudiante no encontrado." });

        // También desactivar el usuario vinculado
        await pool.query(
            `UPDATE public.usuarios SET activo = false WHERE usuario_id = $1`, [id]
        );

        res.json({
            message: "Estudiante eliminado y usuario desactivado.",
            estudiante: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al eliminar estudiante:", error);
        res.status(500).json({ error: "Error interno al eliminar estudiante." });
    }
}

// 6. Perfil del estudiante autenticado (datos reales para "Mi Perfil")
async function obtenerMiPerfil(req, res) {
    const estudiante_id = req.user.id;

    try {
        const datosResult = await pool.query(
            `SELECT e.estudiante_id, e.codigo_estudiante, e.nombre, e.apellido, e.email,
                    e.fecha_ingreso, t.nombre_titulacion, u.activo
             FROM public.estudiantes e
             LEFT JOIN public.titulaciones t ON e.titulacion_id = t.titulacion_id
             LEFT JOIN public.usuarios u ON e.usuario_id = u.usuario_id
             WHERE e.estudiante_id = $1`,
            [estudiante_id]
        );

        if (datosResult.rows.length === 0) {
            return res.status(404).json({ error: "No se encontró el perfil del estudiante." });
        }

        const progresoResult = await pool.query(
            `SELECT a.nombre_asignatura,
                    COUNT(*)::int AS total_recetas,
                    SUM(CASE WHEN v.estado = 'APROBADA' THEN 1 ELSE 0 END)::int AS recetas_aprobadas
             FROM public.estudiante_receta_acceso era
             JOIN public.recetas r ON era.receta_id = r.receta_id
             LEFT JOIN public.asignaturas a ON r.asignatura_id = a.asignatura_id
             LEFT JOIN LATERAL (
                  SELECT * FROM public.recetas_versiones rv
                  WHERE rv.receta_id = r.receta_id
                  ORDER BY rv.version_id DESC
                  LIMIT 1
             ) v ON true
             WHERE era.estudiante_id = $1
             GROUP BY a.nombre_asignatura
             ORDER BY a.nombre_asignatura ASC`,
            [estudiante_id]
        );

        const progresoPorAsignatura = progresoResult.rows;
        const totalRecetas = progresoPorAsignatura.reduce((acc, p) => acc + p.total_recetas, 0);
        const totalAprobadas = progresoPorAsignatura.reduce((acc, p) => acc + p.recetas_aprobadas, 0);
        const porcentajeAvance = totalRecetas > 0 ? Math.round((totalAprobadas / totalRecetas) * 100) : 0;

        res.json({
            perfil: datosResult.rows[0],
            progresoPorAsignatura,
            resumenAcademico: {
                total_recetas: totalRecetas,
                recetas_aprobadas: totalAprobadas,
                porcentaje_avance: porcentajeAvance
            }
        });

    } catch (error) {
        console.error("🔴 Error al obtener el perfil del estudiante:", error);
        res.status(500).json({ error: "Error interno al obtener el perfil." });
    }
}


// 7. Detalle de un estudiante para el expediente del Administrador
//    (incluye las recetas que tiene asignadas)
async function obtenerDetalleEstudiante(req, res) {
    const { id } = req.params;

    try {
        const estudianteResult = await pool.query(
            `SELECT e.*, t.nombre_titulacion
             FROM public.estudiantes e
             LEFT JOIN public.titulaciones t ON e.titulacion_id = t.titulacion_id
             WHERE e.estudiante_id = $1`,
            [id]
        );

        if (estudianteResult.rows.length === 0) {
            return res.status(404).json({ error: "Estudiante no encontrado." });
        }

        const recetasResult = await pool.query(
            `SELECT r.receta_id, r.nombre, a.nombre_asignatura, era.fecha_acceso, v.estado AS estado_version
             FROM public.estudiante_receta_acceso era
             JOIN public.recetas r ON era.receta_id = r.receta_id
             LEFT JOIN public.asignaturas a ON r.asignatura_id = a.asignatura_id
             LEFT JOIN LATERAL (
                  SELECT * FROM public.recetas_versiones rv
                  WHERE rv.receta_id = r.receta_id
                  ORDER BY rv.version_id DESC
                  LIMIT 1
             ) v ON true
             WHERE era.estudiante_id = $1
             ORDER BY era.fecha_acceso DESC`,
            [id]
        );

        res.json({
            estudiante: estudianteResult.rows[0],
            recetas: recetasResult.rows
        });

    } catch (error) {
        console.error("🔴 Error al obtener el detalle del estudiante:", error);
        res.status(500).json({ error: "Error interno al obtener el detalle del estudiante." });
    }
}


module.exports = {
    crearEstudiante,
    obtenerEstudiantes,
    obtenerEstudiantePorId,
    actualizarEstudiante,
    eliminarEstudiante,
    obtenerMiPerfil,
    obtenerDetalleEstudiante
};
