// src/controllers/horariosControllers.js
const pool = require("../db");

/* ═══════════════════════════════════════════════════════════
   1. POST /api/horarios  (Admin/Docente)
   ═══════════════════════════════════════════════════════════ */
async function crearHorario(req, res) {
    const { asignatura_id, dia_semana, hora_inicio, hora_fin, aula } = req.body;
    let { docente_id } = req.body;

    if (!asignatura_id || !dia_semana || !hora_inicio || !hora_fin)
        return res.status(400).json({ error: "asignatura_id, dia_semana, hora_inicio y hora_fin son obligatorios." });

    if (req.user.rol === 2 && !docente_id) docente_id = req.user.id;

    try {
        const result = await pool.query(
            `INSERT INTO public.horarios_clase (asignatura_id, docente_id, dia_semana, hora_inicio, hora_fin, aula)
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
            [asignatura_id, docente_id || null, dia_semana, hora_inicio, hora_fin, aula || null]
        );
        res.status(201).json({ message: "Horario creado.", horario: result.rows[0] });
    } catch (err) {
        console.error("🔴 crearHorario:", err);
        res.status(500).json({ error: "Error al crear el horario." });
    }
}

/* ═══════════════════════════════════════════════════════════
   2. GET /api/horarios  (Admin ve todos, Docente solo los suyos)
   ═══════════════════════════════════════════════════════════ */
async function obtenerHorarios(req, res) {
    try {
        const esDocente = req.user.rol === 2;
        const result = await pool.query(
            `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, h.aula,
                    a.asignatura_id, a.nombre_asignatura, a.titulacion_id,
                    u.usuario_id AS docente_id, u.nombre_completo AS docente_nombre
             FROM public.horarios_clase h
             JOIN  public.asignaturas a ON h.asignatura_id = a.asignatura_id
             LEFT JOIN public.usuarios u ON h.docente_id = u.usuario_id
             ${esDocente ? "WHERE h.docente_id = $1" : ""}
             ORDER BY h.dia_semana, h.hora_inicio`,
            esDocente ? [req.user.id] : []
        );
        res.json(result.rows);
    } catch (err) {
        console.error("🔴 obtenerHorarios:", err);
        res.status(500).json({ error: "Error al obtener horarios." });
    }
}

/* ═══════════════════════════════════════════════════════════
   3. DELETE /api/horarios/:id  (Admin/Docente)
   ═══════════════════════════════════════════════════════════ */
async function eliminarHorario(req, res) {
    const { id } = req.params;
    try {
        const result = await pool.query(
            `DELETE FROM public.horarios_clase WHERE horario_id=$1 RETURNING *`, [id]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: "Horario no encontrado." });
        res.json({ message: "Horario eliminado.", horario: result.rows[0] });
    } catch (err) {
        console.error("🔴 eliminarHorario:", err);
        res.status(500).json({ error: "Error al eliminar el horario." });
    }
}

/* ═══════════════════════════════════════════════════════════
   4. GET /api/horarios/mi-horario  (Estudiante)
   Horario según la titulación del estudiante
   ═══════════════════════════════════════════════════════════ */
async function obtenerMiHorario(req, res) {
    try {
        const estRes = await pool.query(
            `SELECT titulacion_id FROM public.estudiantes WHERE estudiante_id=$1`, [req.user.id]
        );
        if (estRes.rows.length === 0)
            return res.status(404).json({ error: "No se encontró tu información de estudiante." });

        const titulacion_id = estRes.rows[0].titulacion_id;
        if (!titulacion_id) return res.json([]);

        const result = await pool.query(
            `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, h.aula,
                    a.nombre_asignatura,
                    u.nombre_completo AS docente_nombre
             FROM public.horarios_clase h
             JOIN  public.asignaturas a ON h.asignatura_id = a.asignatura_id
             LEFT JOIN public.usuarios u ON h.docente_id = u.usuario_id
             WHERE a.titulacion_id=$1
             ORDER BY h.hora_inicio, h.dia_semana`,
            [titulacion_id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error("🔴 obtenerMiHorario:", err);
        res.status(500).json({ error: "Error al obtener tu horario." });
    }
}

/* ═══════════════════════════════════════════════════════════
   5. GET /api/horarios/mis-grupos  (Docente)
   Agrupa los horarios del docente por asignatura e incluye
   cantidad de estudiantes que tienen esa titulación
   ═══════════════════════════════════════════════════════════ */
async function obtenerMisGrupos(req, res) {
    try {
        const result = await pool.query(
            `SELECT
                a.asignatura_id,
                a.nombre_asignatura,
                t.nombre_titulacion,
                COUNT(DISTINCT h.horario_id)::int                       AS bloques_horario,
                STRING_AGG(DISTINCT h.dia_semana || ' ' ||
                    SUBSTRING(h.hora_inicio::text, 1, 5) || '-' ||
                    SUBSTRING(h.hora_fin::text, 1, 5), ', ')            AS horario_resumen,
                COUNT(DISTINCT e.estudiante_id)::int                     AS total_estudiantes
             FROM public.horarios_clase h
             JOIN  public.asignaturas a   ON h.asignatura_id = a.asignatura_id
             LEFT JOIN public.titulaciones t ON a.titulacion_id = t.titulacion_id
             LEFT JOIN public.estudiantes  e ON e.titulacion_id = a.titulacion_id
             WHERE h.docente_id = $1
             GROUP BY a.asignatura_id, a.nombre_asignatura, t.nombre_titulacion
             ORDER BY a.nombre_asignatura`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error("🔴 obtenerMisGrupos:", err);
        res.status(500).json({ error: "Error al obtener tus grupos." });
    }
}

/* ═══════════════════════════════════════════════════════════
   6. GET /api/horarios/mis-grupos/:asignatura_id/estudiantes
   Lista los estudiantes de la titulación de esa asignatura
   ═══════════════════════════════════════════════════════════ */
async function obtenerEstudiantesDeGrupo(req, res) {
    const { asignatura_id } = req.params;
    try {
        const result = await pool.query(
            `SELECT e.estudiante_id, e.nombre, e.apellido, e.codigo_estudiante,
                    COUNT(era.receta_id)::int AS total_recetas_asignadas
             FROM public.asignaturas a
             JOIN  public.estudiantes e  ON e.titulacion_id = a.titulacion_id
             LEFT JOIN public.estudiante_receta_acceso era ON era.estudiante_id = e.estudiante_id
             WHERE a.asignatura_id = $1
             GROUP BY e.estudiante_id, e.nombre, e.apellido, e.codigo_estudiante
             ORDER BY e.apellido, e.nombre`,
            [asignatura_id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error("🔴 obtenerEstudiantesDeGrupo:", err);
        res.status(500).json({ error: "Error al obtener los estudiantes del grupo." });
    }
}

module.exports = {
    crearHorario,
    obtenerHorarios,
    eliminarHorario,
    obtenerMiHorario,
    obtenerMisGrupos,
    obtenerEstudiantesDeGrupo
};
