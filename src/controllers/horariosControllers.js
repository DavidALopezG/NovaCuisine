// src/controllers/horariosControllers.js
const pool = require("../db");

/* ============================================================
   1. POST /api/horarios  (Admin/Docente)
   Crea un bloque de horario para una asignatura
   ============================================================ */
async function crearHorario(req, res) {
    const { asignatura_id, dia_semana, hora_inicio, hora_fin, aula } = req.body;
    let { docente_id } = req.body;

    if (!asignatura_id || !dia_semana || !hora_inicio || !hora_fin) {
        return res.status(400).json({
            error: "asignatura_id, dia_semana, hora_inicio y hora_fin son obligatorios."
        });
    }

    // Si quien crea es Docente (rol 2) y no especifica otro docente, se asigna a sí mismo
    if (req.user.rol === 2 && !docente_id) {
        docente_id = req.user.id;
    }

    try {
        const result = await pool.query(
            `INSERT INTO public.horarios_clase
                (asignatura_id, docente_id, dia_semana, hora_inicio, hora_fin, aula)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *`,
            [asignatura_id, docente_id || null, dia_semana, hora_inicio, hora_fin, aula || null]
        );

        res.status(201).json({ message: "Horario creado correctamente.", horario: result.rows[0] });
    } catch (error) {
        console.error("🔴 Error al crear horario:", error);
        res.status(500).json({ error: "Error interno al crear el horario." });
    }
}

/* ============================================================
   2. GET /api/horarios  (Admin ve todos, Docente solo los suyos)
   ============================================================ */
async function obtenerHorarios(req, res) {
    try {
        const filtroDocente = req.user.rol === 2;

        const result = await pool.query(
            `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, h.aula,
                    a.asignatura_id, a.nombre_asignatura, a.titulacion_id,
                    u.usuario_id AS docente_id, u.nombre_completo AS docente_nombre,
                    (
                      SELECT COUNT(*)::int FROM public.estudiantes e
                      WHERE e.titulacion_id = a.titulacion_id
                    ) AS alumnos_estimados
             FROM public.horarios_clase h
             JOIN public.asignaturas a ON h.asignatura_id = a.asignatura_id
             LEFT JOIN public.usuarios u ON h.docente_id = u.usuario_id
             ${filtroDocente ? "WHERE h.docente_id = $1" : ""}
             ORDER BY h.dia_semana, h.hora_inicio`,
            filtroDocente ? [req.user.id] : []
        );

        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener horarios:", error);
        res.status(500).json({ error: "Error al obtener los horarios." });
    }
}

/* ============================================================
   3. DELETE /api/horarios/:id  (Admin/Docente)
   El Docente solo puede eliminar SUS PROPIOS bloques de horario.
   El Admin puede eliminar cualquiera.
   ============================================================ */
async function eliminarHorario(req, res) {
    const { id } = req.params;

    try {
        const existente = await pool.query(
            `SELECT docente_id FROM public.horarios_clase WHERE horario_id = $1`,
            [id]
        );

        if (existente.rows.length === 0) {
            return res.status(404).json({ error: "Horario no encontrado." });
        }

        if (req.user.rol === 2 && Number(existente.rows[0].docente_id) !== Number(req.user.id)) {
            return res.status(403).json({ error: "No puedes eliminar un grupo/horario que no te pertenece." });
        }

        const result = await pool.query(
            `DELETE FROM public.horarios_clase WHERE horario_id = $1 RETURNING *`,
            [id]
        );

        res.json({ message: "Horario eliminado.", horario: result.rows[0] });
    } catch (error) {
        console.error("🔴 Error al eliminar horario:", error);
        res.status(500).json({ error: "Error interno al eliminar el horario." });
    }
}

/* ============================================================
   3b. PUT /api/horarios/:id  (Admin/Docente)
   Permite "configurar" un grupo/bloque ya creado: cambiar
   asignatura, día, horas o aula. El Docente solo puede editar
   SUS PROPIOS bloques; no puede reasignar el docente_id a otra
   persona (eso queda reservado al Admin).
   ============================================================ */
async function actualizarHorario(req, res) {
    const { id } = req.params;
    const { asignatura_id, dia_semana, hora_inicio, hora_fin, aula } = req.body;
    let { docente_id } = req.body;

    if (!asignatura_id || !dia_semana || !hora_inicio || !hora_fin) {
        return res.status(400).json({
            error: "asignatura_id, dia_semana, hora_inicio y hora_fin son obligatorios."
        });
    }

    try {
        const existente = await pool.query(
            `SELECT docente_id FROM public.horarios_clase WHERE horario_id = $1`,
            [id]
        );

        if (existente.rows.length === 0) {
            return res.status(404).json({ error: "Horario no encontrado." });
        }

        if (req.user.rol === 2) {
            if (Number(existente.rows[0].docente_id) !== Number(req.user.id)) {
                return res.status(403).json({ error: "No puedes editar un grupo/horario que no te pertenece." });
            }
            // Un docente jamás puede reasignar el grupo a otro docente desde este endpoint
            docente_id = existente.rows[0].docente_id;
        }

        const result = await pool.query(
            `UPDATE public.horarios_clase
                SET asignatura_id = $1,
                    docente_id    = $2,
                    dia_semana    = $3,
                    hora_inicio   = $4,
                    hora_fin      = $5,
                    aula          = $6
              WHERE horario_id = $7
              RETURNING *`,
            [asignatura_id, docente_id || existente.rows[0].docente_id, dia_semana, hora_inicio, hora_fin, aula || null, id]
        );

        res.json({ message: "Grupo/horario actualizado correctamente.", horario: result.rows[0] });
    } catch (error) {
        console.error("🔴 Error al actualizar horario:", error);
        res.status(500).json({ error: "Error interno al actualizar el horario." });
    }
}

/* ============================================================
   4. GET /api/horarios/mi-horario  (Estudiante)
   Devuelve el horario real según las asignaturas de SU titulación
   ============================================================ */
async function obtenerMiHorario(req, res) {
    try {
        const estudiante_id = req.user.id;

        const tituResult = await pool.query(
            `SELECT titulacion_id FROM public.estudiantes WHERE estudiante_id = $1`,
            [estudiante_id]
        );

        if (tituResult.rows.length === 0) {
            return res.status(404).json({ error: "No se encontró tu información de estudiante." });
        }

        const titulacion_id = tituResult.rows[0].titulacion_id;

        if (!titulacion_id) {
            return res.json([]); // El estudiante no tiene titulación asignada aún
        }

        const result = await pool.query(
            `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, h.aula,
                    a.nombre_asignatura,
                    u.nombre_completo AS docente_nombre
             FROM public.horarios_clase h
             JOIN public.asignaturas a ON h.asignatura_id = a.asignatura_id
             LEFT JOIN public.usuarios u ON h.docente_id = u.usuario_id
             WHERE a.titulacion_id = $1
             ORDER BY h.hora_inicio, h.dia_semana`,
            [titulacion_id]
        );

        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener mi horario:", error);
        res.status(500).json({ error: "Error al obtener tu horario." });
    }
}

module.exports = {
    crearHorario,
    obtenerHorarios,
    actualizarHorario,
    eliminarHorario,
    obtenerMiHorario
};
