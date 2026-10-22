// src/controllers/horariosControllers.js
const pool = require("../db");
const { esHoraValida, DIAS_VALIDOS } = require("../utils/validaciones");

/**
 * Validaciones de formato y de referencias comunes a crear/editar un bloque.
 * Devuelve un mensaje de error (string) o null si todo está bien.
 */
const normalizarHora = (h) => (typeof h === "string" && /^\d{2}:\d{2}$/.test(h) ? `${h}:00` : h);

async function validarDatosHorario({ asignatura_id, dia_semana, hora_inicio, hora_fin, docente_id }) {
    if (!DIAS_VALIDOS.includes(dia_semana)) {
        return `dia_semana debe ser uno de: ${DIAS_VALIDOS.join(", ")}.`;
    }
    if (!esHoraValida(hora_inicio) || !esHoraValida(hora_fin)) {
        return "hora_inicio y hora_fin deben tener formato HH:MM (24 h).";
    }
    // Se normaliza a HH:MM:SS para comparar bien como texto ("9:00" > "10:00" ya no es posible)
    const asig = await pool.query(`SELECT 1 FROM public.asignaturas WHERE asignatura_id = $1`, [asignatura_id]);
    if (asig.rows.length === 0) {
        return "La asignatura seleccionada no existe.";
    }
    if (docente_id) {
        const doc = await pool.query(
            `SELECT rol_id, activo FROM public.usuarios WHERE usuario_id = $1`,
            [docente_id]
        );
        if (doc.rows.length === 0) return "El docente seleccionado no existe.";
        if (Number(doc.rows[0].rol_id) !== 2) return "El usuario seleccionado no tiene rol de Docente.";
        if (doc.rows[0].activo === false) return "El docente seleccionado está desactivado.";
    }
    return null;
}

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
        params.push(String(aula).trim().toLowerCase());
        condicionesChoque.push(`LOWER(TRIM(aula)) = $${params.length}`);
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
    const { asignatura_id, dia_semana, aula } = req.body;
    let { docente_id, modalidad } = req.body;
    const hora_inicio = normalizarHora(req.body.hora_inicio);
    const hora_fin    = normalizarHora(req.body.hora_fin);

    if (!asignatura_id || !dia_semana || !hora_inicio || !hora_fin) {
        return res.status(400).json({
            error: "asignatura_id, dia_semana, hora_inicio y hora_fin son obligatorios."
        });
    }

    if (modalidad && !["Presencial", "Intensivo"].includes(modalidad)) {
        return res.status(400).json({ error: "modalidad debe ser 'Presencial' o 'Intensivo'." });
    }
    modalidad = modalidad || "Presencial";

    // Si quien crea es Docente (rol 2) y no especifica otro docente, se asigna a sí mismo
    if (req.user.rol === 2) {
        // Un Docente solo crea bloques a su nombre (igual que en la edición, donde no puede reasignarlos)
        if (docente_id && String(docente_id) !== String(req.user.id)) {
            return res.status(403).json({ error: "Un docente solo puede crear horarios asignados a sí mismo." });
        }
        docente_id = req.user.id;
    }

    try {
        const errorDatos = await validarDatosHorario({ asignatura_id, dia_semana, hora_inicio, hora_fin, docente_id });
        if (errorDatos) {
            return res.status(400).json({ error: errorDatos });
        }

        const errorConflicto = await validarHorarioSinConflicto({ dia_semana, hora_inicio, hora_fin, docente_id, aula });
        if (errorConflicto) {
            return res.status(409).json({ error: errorConflicto });
        }

        const result = await pool.query(
            `INSERT INTO public.horarios_clase
                (asignatura_id, docente_id, dia_semana, hora_inicio, hora_fin, aula, modalidad)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [asignatura_id, docente_id || null, dia_semana, hora_inicio, hora_fin, aula ? String(aula).trim() : null, modalidad]
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
            `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, h.aula, h.modalidad,
                    a.asignatura_id, a.nombre_asignatura, a.titulacion_id,
                    u.usuario_id AS docente_id, u.nombre_completo AS docente_nombre,
                    (
                      SELECT COUNT(*)::int FROM public.matriculas_horario m
                      WHERE m.horario_id = h.horario_id
                    ) AS alumnos_matriculados,
                    ${CUPO_MAXIMO_POR_HORARIO} AS cupo_maximo
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

        const matriculas = await pool.query(
            `SELECT COUNT(*)::int AS total FROM public.matriculas_horario WHERE horario_id = $1`,
            [id]
        );
        if (matriculas.rows[0].total > 0) {
            return res.status(409).json({
                error: `No se puede eliminar: el grupo tiene ${matriculas.rows[0].total} estudiante(s) matriculado(s). Retíralos primero.`
            });
        }

        const result = await pool.query(
            `DELETE FROM public.horarios_clase WHERE horario_id = $1 RETURNING *`,
            [id]
        );

        res.json({ message: "Horario eliminado.", horario: result.rows[0] });
    } catch (error) {
        if (error.code === "23503") {
            return res.status(409).json({ error: "No se puede eliminar: el grupo tiene registros vinculados." });
        }
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
    const { asignatura_id, dia_semana, aula } = req.body;
    let { docente_id, modalidad } = req.body;
    const hora_inicio = normalizarHora(req.body.hora_inicio);
    const hora_fin    = normalizarHora(req.body.hora_fin);

    if (!asignatura_id || !dia_semana || !hora_inicio || !hora_fin) {
        return res.status(400).json({
            error: "asignatura_id, dia_semana, hora_inicio y hora_fin son obligatorios."
        });
    }

    if (modalidad && !["Presencial", "Intensivo"].includes(modalidad)) {
        return res.status(400).json({ error: "modalidad debe ser 'Presencial' o 'Intensivo'." });
    }

    try {
        const existente = await pool.query(
            `SELECT docente_id, modalidad FROM public.horarios_clase WHERE horario_id = $1`,
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

        modalidad = modalidad || existente.rows[0].modalidad || "Presencial";

        const docenteFinal = docente_id || existente.rows[0].docente_id;

        const errorDatos = await validarDatosHorario({
            asignatura_id, dia_semana, hora_inicio, hora_fin, docente_id: docenteFinal
        });
        if (errorDatos) {
            return res.status(400).json({ error: errorDatos });
        }

        const errorConflicto = await validarHorarioSinConflicto({
            dia_semana, hora_inicio, hora_fin,
            docente_id: docenteFinal,
            aula,
            excluirHorarioId: id
        });
        if (errorConflicto) {
            return res.status(409).json({ error: errorConflicto });
        }

        // Si cambian día/hora, los alumnos ya matriculados podrían quedar con cruces en su propio horario
        if (!req.body.forzar) {
            const matriculados = await pool.query(
                `SELECT m.estudiante_id, e.nombre, e.apellido
                 FROM public.matriculas_horario m
                 JOIN public.estudiantes e ON e.estudiante_id = m.estudiante_id
                 WHERE m.horario_id = $1`,
                [id]
            );
            const afectados = [];
            for (const est of matriculados.rows) {
                const cruces = await buscarConflictoHorarioEstudiante(pool, est.estudiante_id, {
                    horario_id: Number(id), dia_semana, hora_inicio, hora_fin
                });
                if (cruces.length > 0) afectados.push(`${est.nombre} ${est.apellido}`);
            }
            if (afectados.length > 0) {
                return res.status(409).json({
                    error: `Con este cambio ${afectados.length} estudiante(s) matriculado(s) tendrían cruce de horario: ${afectados.slice(0, 5).join(", ")}${afectados.length > 5 ? "…" : ""}.`,
                    tipo: "CRUCE_HORARIO_MATRICULADOS",
                    afectados
                });
            }
        }

        const result = await pool.query(
            `UPDATE public.horarios_clase
                SET asignatura_id = $1,
                    docente_id    = $2,
                    dia_semana    = $3,
                    hora_inicio   = $4,
                    hora_fin      = $5,
                    aula          = $6,
                    modalidad     = $7
              WHERE horario_id = $8
              RETURNING *`,
            [asignatura_id, docenteFinal, dia_semana, hora_inicio, hora_fin, aula ? String(aula).trim() : null, modalidad, id]
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
// Cupo máximo por horario/grupo, según reglas institucionales (folleto de inscripción).
const CUPO_MAXIMO_POR_HORARIO = 6;

/**
 * Busca si el estudiante ya está matriculado en OTRO horario que se
 * solapa en día/hora con el horario destino. Se usa para advertir de
 * cruces de horario a nivel de estudiante (patrón "permitir + confirmar",
 * igual que el cruce de titulación ya existente en el frontend).
 */
async function buscarConflictoHorarioEstudiante(client, estudianteId, horarioDestino) {
    const result = await client.query(
        `SELECT h.horario_id, h.dia_semana, h.hora_inicio, h.hora_fin, a.nombre_asignatura
         FROM public.matriculas_horario m
         JOIN public.horarios_clase h ON h.horario_id = m.horario_id
         LEFT JOIN public.asignaturas a ON a.asignatura_id = h.asignatura_id
         WHERE m.estudiante_id = $1
           AND h.horario_id <> $2
           AND h.dia_semana = $3
           AND h.hora_inicio < $4
           AND h.hora_fin > $5`,
        [
            estudianteId,
            horarioDestino.horario_id,
            horarioDestino.dia_semana,
            horarioDestino.hora_fin,
            horarioDestino.hora_inicio
        ]
    );
    return result.rows;
}

/**
 * Matricula a un estudiante en un horario/grupo respetando el cupo máximo.
 * Usa un client dedicado con transacción + FOR UPDATE sobre el horario para
 * evitar condición de carrera: si dos matrículas llegan casi al mismo tiempo
 * cuando queda 1 cupo, solo una debe pasar.
 *
 * También valida cruces de horario a nivel de estudiante (mismo estudiante
 * matriculado en dos grupos que se solapan en día/hora). Sigue el patrón
 * "permitir + confirmar": si hay cruce y el body no trae forzar=true,
 * responde 409 con el detalle del cruce para que el frontend muestre
 * confirmación; si el usuario confirma, reenvía la petición con forzar=true.
 */
async function matricularEstudiante(req, res) {
    const { id } = req.params;
    const { estudiante_id, forzar } = req.body;

    if (!estudiante_id) {
        return res.status(400).json({ error: "estudiante_id es obligatorio." });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        // FOR UPDATE bloquea la fila del horario para serializar matrículas concurrentes
        const horario = await client.query(
            `SELECT horario_id, docente_id, dia_semana, hora_inicio, hora_fin
             FROM public.horarios_clase WHERE horario_id = $1 FOR UPDATE`,
            [id]
        );
        if (horario.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: "Horario no encontrado." });
        }
        if (req.user.rol === 2 && Number(horario.rows[0].docente_id) !== Number(req.user.id)) {
            await client.query("ROLLBACK");
            return res.status(403).json({ error: "No puedes matricular estudiantes en un grupo que no te pertenece." });
        }

        // ¿Ya está matriculado? Si sí, no cuenta contra el cupo, solo se informa.
        const yaMatriculado = await client.query(
            `SELECT 1 FROM public.matriculas_horario WHERE horario_id = $1 AND estudiante_id = $2`,
            [id, estudiante_id]
        );
        if (yaMatriculado.rows.length > 0) {
            await client.query("ROLLBACK");
            return res.status(200).json({
                message: "El estudiante ya estaba matriculado en este grupo.",
                matricula: null
            });
        }

        // El estudiante debe existir y tener la cuenta activa
        const est = await client.query(
            `SELECT e.titulacion_id, COALESCE(u.activo, true) AS activo
             FROM public.estudiantes e
             LEFT JOIN public.usuarios u ON u.usuario_id = e.estudiante_id
             WHERE e.estudiante_id = $1`,
            [estudiante_id]
        );
        if (est.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: "El estudiante no existe." });
        }
        if (est.rows[0].activo === false) {
            await client.query("ROLLBACK");
            return res.status(400).json({ error: "El estudiante tiene la cuenta desactivada." });
        }

        // No puede estar en dos grupos de la MISMA asignatura (bloqueo duro)
        const mismaAsig = await client.query(
            `SELECT h2.horario_id
             FROM public.horarios_clase h1
             JOIN public.horarios_clase h2 ON h2.asignatura_id = h1.asignatura_id AND h2.horario_id <> h1.horario_id
             JOIN public.matriculas_horario m ON m.horario_id = h2.horario_id AND m.estudiante_id = $2
             WHERE h1.horario_id = $1`,
            [id, estudiante_id]
        );
        if (mismaAsig.rows.length > 0) {
            await client.query("ROLLBACK");
            return res.status(409).json({
                error: "El estudiante ya está matriculado en otro grupo de esta misma asignatura.",
                tipo: "MISMA_ASIGNATURA"
            });
        }

        // Cruce de horario a nivel de estudiante: permitir + confirmar.
        if (!forzar) {
            const cruces = await buscarConflictoHorarioEstudiante(client, estudiante_id, horario.rows[0]);
            if (cruces.length > 0) {
                await client.query("ROLLBACK");
                return res.status(409).json({
                    error: "El estudiante ya tiene otro grupo matriculado que se cruza en día y hora con este horario.",
                    tipo: "CRUCE_HORARIO_ESTUDIANTE",
                    cruces
                });
            }
        }

        const conteo = await client.query(
            `SELECT COUNT(*)::int AS total FROM public.matriculas_horario WHERE horario_id = $1`,
            [id]
        );
        if (conteo.rows[0].total >= CUPO_MAXIMO_POR_HORARIO) {
            await client.query("ROLLBACK");
            return res.status(409).json({
                error: `Cupo máximo alcanzado (${CUPO_MAXIMO_POR_HORARIO} estudiantes) para este horario.`
            });
        }

        const result = await client.query(
            `INSERT INTO public.matriculas_horario (horario_id, estudiante_id)
             VALUES ($1, $2)
             ON CONFLICT (horario_id, estudiante_id) DO NOTHING
             RETURNING *`,
            [id, estudiante_id]
        );

        await client.query("COMMIT");

        res.status(201).json({
            message: result.rows.length > 0
                ? "Estudiante matriculado correctamente."
                : "El estudiante ya estaba matriculado en este grupo.",
            matricula: result.rows[0] || null
        });
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.code === "23503") {
            return res.status(400).json({ error: "El horario o el estudiante no existen." });
        }
        console.error("🔴 Error al matricular estudiante:", error);
        res.status(500).json({ error: "Error interno al matricular al estudiante." });
    } finally {
        client.release();
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
