// src/controllers/horariosControllers.js
const pool = require("../db");

/**
 * Valida hora_fin > hora_inicio y que no exista un choque de horario:
 * mismo día + mismo docente (si tiene) O misma aula (si tiene), con
 * un rango de horas que se solapa con otro bloque ya existente.
 * `excluirHorarioId` se usa al editar, para no chocar contra sí mismo.
 */
async function validarHorarioSinConflicto({ dia_semana, hora_inicio, hora_fin, docente_id, aula, excluirHorarioId }) {
    if (hora_fin <= hora_inicio) {
        return "La hora de fin debe ser posterior a la hora de inicio.";
    }

    const condiciones = [`dia_semana = $1`, `hora_inicio < $2`, `hora_fin > $3`];
    const params = [dia_semana, hora_fin, hora_inicio];

    const condicionesChoque = [];
    if (docente_id) {
        params.push(docente_id);
        condicionesChoque.push(`docente_id = $${params.length}`);
    }
    if (aula) {
        params.push(aula);
        condicionesChoque.push(`aula = $${params.length}`);
    }
    if (condicionesChoque.length === 0) {
        return null; // Sin docente ni aula asignados todavía, no hay contra qué comparar
    }
    condiciones.push(`(${condicionesChoque.join(" OR ")})`);

    let query = `SELECT horario_id FROM public.horarios_clase WHERE ${condiciones.join(" AND ")}`;
    if (excluirHorarioId) {
        params.push(excluirHorarioId);
        query += ` AND horario_id <> $${params.length}`;
    }

    const choque = await pool.query(query, params);
    if (choque.rows.length > 0) {
        return "Ya existe otro bloque de horario en ese día/hora para el mismo docente o la misma aula.";
    }
    return null;
}

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

    const errorConflicto = await validarHorarioSinConflicto({ dia_semana, hora_inicio, hora_fin, docente_id, aula });
    if (errorConflicto) {
        return res.status(409).json({ error: errorConflicto });
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
                      SELECT COUNT(*)::int FROM public.matriculas_horario m
                      WHERE m.horario_id = h.horario_id
                    ) AS alumnos_matriculados
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

        const errorConflicto = await validarHorarioSinConflicto({
            dia_semana, hora_inicio, hora_fin,
            docente_id: docente_id || existente.rows[0].docente_id,
            aula,
            excluirHorarioId: id
        });
        if (errorConflicto) {
            return res.status(409).json({ error: errorConflicto });
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
   Devuelve el horario real según la MATRÍCULA del estudiante
   (antes se calculaba por titulación; ahora es matrícula explícita
   por grupo/horario, así distintas secciones de la misma asignatura
   no se mezclan entre sí).
   ============================================================ */
async function obtenerMiHorario(req, res) {
    try {
        const estudiante_id = req.user.id;

        const result = await pool.query(
            `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, h.aula,
                    a.nombre_asignatura,
                    u.nombre_completo AS docente_nombre
             FROM public.matriculas_horario m
             JOIN public.horarios_clase h ON m.horario_id = h.horario_id
             JOIN public.asignaturas a ON h.asignatura_id = a.asignatura_id
             LEFT JOIN public.usuarios u ON h.docente_id = u.usuario_id
             WHERE m.estudiante_id = $1
             ORDER BY h.hora_inicio, h.dia_semana`,
            [estudiante_id]
        );

        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener mi horario:", error);
        res.status(500).json({ error: "Error al obtener tu horario." });
    }
}

/* ============================================================
   5. GET /api/horarios/:id/estudiantes  (Admin/Docente)
   Lista los estudiantes matriculados en un bloque de horario/grupo
   ============================================================ */
async function obtenerEstudiantesDeHorario(req, res) {
    const { id } = req.params;

    try {
        const horario = await pool.query(
            `SELECT docente_id FROM public.horarios_clase WHERE horario_id = $1`,
            [id]
        );
        if (horario.rows.length === 0) {
            return res.status(404).json({ error: "Horario no encontrado." });
        }
        if (req.user.rol === 2 && Number(horario.rows[0].docente_id) !== Number(req.user.id)) {
            return res.status(403).json({ error: "No puedes ver la matrícula de un grupo que no te pertenece." });
        }

        const result = await pool.query(
            `SELECT m.matricula_id, e.estudiante_id, e.codigo_estudiante, e.nombre, e.apellido, m.fecha_matricula
             FROM public.matriculas_horario m
             JOIN public.estudiantes e ON m.estudiante_id = e.estudiante_id
             WHERE m.horario_id = $1
             ORDER BY e.apellido, e.nombre`,
            [id]
        );

        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener estudiantes del horario:", error);
        res.status(500).json({ error: "Error al obtener los estudiantes matriculados." });
    }
}

/* ============================================================
   6. POST /api/horarios/:id/estudiantes  (Admin/Docente)
   Matricula un estudiante en un bloque de horario/grupo
   ============================================================ */
async function matricularEstudiante(req, res) {
    const { id } = req.params;
    const { estudiante_id } = req.body;

    if (!estudiante_id) {
        return res.status(400).json({ error: "estudiante_id es obligatorio." });
    }

    try {
        const horario = await pool.query(
            `SELECT docente_id FROM public.horarios_clase WHERE horario_id = $1`,
            [id]
        );
        if (horario.rows.length === 0) {
            return res.status(404).json({ error: "Horario no encontrado." });
        }
        if (req.user.rol === 2 && Number(horario.rows[0].docente_id) !== Number(req.user.id)) {
            return res.status(403).json({ error: "No puedes matricular estudiantes en un grupo que no te pertenece." });
        }

        const result = await pool.query(
            `INSERT INTO public.matriculas_horario (horario_id, estudiante_id)
             VALUES ($1, $2)
             ON CONFLICT (horario_id, estudiante_id) DO NOTHING
             RETURNING *`,
            [id, estudiante_id]
        );

        res.status(201).json({
            message: result.rows.length > 0
                ? "Estudiante matriculado correctamente."
                : "El estudiante ya estaba matriculado en este grupo.",
            matricula: result.rows[0] || null
        });
    } catch (error) {
        if (error.code === "23503") {
            return res.status(400).json({ error: "El horario o el estudiante no existen." });
        }
        console.error("🔴 Error al matricular estudiante:", error);
        res.status(500).json({ error: "Error interno al matricular al estudiante." });
    }
}

/* ============================================================
   7. DELETE /api/horarios/:id/estudiantes/:estudiante_id  (Admin/Docente)
   Retira a un estudiante de un bloque de horario/grupo
   ============================================================ */
async function retirarEstudiante(req, res) {
    const { id, estudiante_id } = req.params;

    try {
        const horario = await pool.query(
            `SELECT docente_id FROM public.horarios_clase WHERE horario_id = $1`,
            [id]
        );
        if (horario.rows.length === 0) {
            return res.status(404).json({ error: "Horario no encontrado." });
        }
        if (req.user.rol === 2 && Number(horario.rows[0].docente_id) !== Number(req.user.id)) {
            return res.status(403).json({ error: "No puedes retirar estudiantes de un grupo que no te pertenece." });
        }

        const result = await pool.query(
            `DELETE FROM public.matriculas_horario WHERE horario_id = $1 AND estudiante_id = $2 RETURNING *`,
            [id, estudiante_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "El estudiante no estaba matriculado en este grupo." });
        }

        res.json({ message: "Estudiante retirado del grupo.", matricula: result.rows[0] });
    } catch (error) {
        console.error("🔴 Error al retirar estudiante:", error);
        res.status(500).json({ error: "Error interno al retirar al estudiante." });
    }
}

module.exports = {
    crearHorario,
    obtenerHorarios,
    actualizarHorario,
    eliminarHorario,
    obtenerMiHorario,
    obtenerEstudiantesDeHorario,
    matricularEstudiante,
    retirarEstudiante
};
