const pool = require("../db");
const bcrypt = require("bcrypt");
const { normalizarEmail, emailValido, cedulaEcuatorianaValida, contrasenaValida } = require("../utils/validaciones");

const ROLES_VALIDOS = [1, 2, 3];

// 1. Crear Usuario (solo Admin)
async function crearUsuario(req, res) {
    const { usuario_id, nombre_completo, contrasena, rol_id, activo, titulacion_id } = req.body;
    const email = normalizarEmail(req.body.email);

    if (!usuario_id || !nombre_completo || !email || !contrasena || !rol_id) {
        return res.status(400).json({
            error: "usuario_id, nombre_completo, email, contrasena y rol_id son obligatorios."
        });
    }
    if (!cedulaEcuatorianaValida(usuario_id)) {
        return res.status(400).json({ error: "La cédula / ID no es una cédula ecuatoriana válida." });
    }
    if (String(nombre_completo).trim().length < 3 || String(nombre_completo).length > 100) {
        return res.status(400).json({ error: "El nombre completo debe tener entre 3 y 100 caracteres." });
    }
    if (!emailValido(email)) {
        return res.status(400).json({ error: "El correo electrónico no es válido." });
    }
    if (!contrasenaValida(contrasena)) {
        return res.status(400).json({ error: "La contraseña debe tener mínimo 8 caracteres, con letras y números." });
    }
    if (!ROLES_VALIDOS.includes(Number(rol_id))) {
        return res.status(400).json({ error: "rol_id debe ser 1 (Administrador), 2 (Docente) o 3 (Estudiante)." });
    }

    const client = await pool.connect();
    try {
        // Si es estudiante, la titulación debe existir (antes se asumía la 1 a ciegas)
        if (Number(rol_id) === 3) {
            if (!titulacion_id) {
                return res.status(400).json({ error: "Selecciona la titulación del estudiante." });
            }
            const t = await client.query(`SELECT 1 FROM public.titulaciones WHERE titulacion_id = $1`, [titulacion_id]);
            if (t.rows.length === 0) {
                return res.status(400).json({ error: "La titulación seleccionada no existe." });
            }
        }

        await client.query("BEGIN");

        const contrasenaHash = await bcrypt.hash(contrasena, 10);

        const usuarioResult = await client.query(
            `INSERT INTO public.usuarios (usuario_id, nombre_completo, email, contrasena_hash, rol_id, activo)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING usuario_id, nombre_completo, email, rol_id, activo`,
            [usuario_id, nombre_completo, email, contrasenaHash, rol_id, activo ?? true]
        );

        let mensajeExtra = "";

        // Si el rol es Estudiante (3), se crea automáticamente su ficha en ESTUDIANTES
        // (igual que en el autorregistro). La titulación por defecto se podrá elegir
        // correctamente cuando construyamos el módulo de Titulaciones.
        if (Number(rol_id) === 3) {
            const partes = nombre_completo.trim().split(/\s+/);
            const nombre = partes[0];
            const apellido = partes.slice(1).join(" ") || " ";
            const codigoEstudiante = `EST-${Date.now().toString().slice(-5)}${Math.floor(Math.random() * 90 + 10)}`;

            await client.query(
                `INSERT INTO public.estudiantes
                    (estudiante_id, usuario_id, nombre, apellido, email, titulacion_id, fecha_ingreso, codigo_estudiante, cedula)
                 VALUES ($1, $1, $2, $3, $4, $5, NOW(), $6, $1)`,
                [usuario_id, nombre, apellido, email, titulacion_id, codigoEstudiante]
            );

            mensajeExtra = ` Se generó también su ficha de estudiante (código ${codigoEstudiante}).`;
        }

        await client.query("COMMIT");

        res.status(201).json({
            message: "Usuario creado exitosamente." + mensajeExtra,
            usuario: usuarioResult.rows[0]
        });

    } catch (error) {
        await client.query("ROLLBACK");
        if (error.code === "23505") {
            const detalle = (error.detail || "").toLowerCase();
            if (detalle.includes("email")) {
                return res.status(409).json({ error: "Ya existe un usuario con ese correo electrónico." });
            }
            if (detalle.includes("codigo")) {
                return res.status(409).json({ error: "Código de estudiante repetido, intenta de nuevo." });
            }
            return res.status(409).json({ error: "Ya existe un usuario registrado con esa cédula / ID." });
        }
        console.error("🔴 Error al crear usuario:", error);
        res.status(500).json({ error: "Error interno al crear el usuario." });
    } finally {
        client.release();
    }
}


// 2. Obtener todos los usuarios
async function obtenerUsuarios(req, res) {
    try {
        const result = await pool.query(
            `SELECT usuario_id, nombre_completo, email, rol_id, activo 
            FROM public.usuarios      
            ORDER BY usuario_id ASC`
        );

        res.json(result.rows);

    } catch (error) {
        console.error("🔴 Error al obtener usuarios:", error);
        res.status(500).json({ error: "Error al obtener usuarios." });
    }
}


// 3. Obtener usuario por ID
async function obtenerUsuarioPorId(req, res) {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `SELECT usuario_id, nombre_completo, email, rol_id, activo 
             FROM public.usuarios WHERE usuario_id = $1`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }

        res.json(result.rows[0]);

    } catch (error) {
        console.error("🔴 Error al obtener usuario:", error);
        res.status(500).json({ error: "Error al obtener usuario." });
    }
}


// 4. Actualizar Usuario
async function actualizarUsuario(req, res) {
    const { id } = req.params;
    const { nombre_completo, rol_id, activo, contrasena } = req.body;
    const email = normalizarEmail(req.body.email);

    if (!nombre_completo || String(nombre_completo).trim().length < 3 || !email || !rol_id) {
        return res.status(400).json({ error: "nombre_completo, email y rol_id son obligatorios." });
    }
    if (!emailValido(email)) {
        return res.status(400).json({ error: "El correo electrónico no es válido." });
    }
    if (!ROLES_VALIDOS.includes(Number(rol_id))) {
        return res.status(400).json({ error: "rol_id debe ser 1, 2 o 3." });
    }
    if (contrasena && contrasena.trim() !== "" && !contrasenaValida(contrasena)) {
        return res.status(400).json({ error: "La contraseña debe tener mínimo 8 caracteres, con letras y números." });
    }
    const activoFinal = typeof activo === "boolean" ? activo : (activo === undefined ? true : String(activo) === "true");

    // Un admin no puede quitarse a sí mismo el acceso (quedaría el sistema sin administrador)
    if (String(id) === String(req.user.id) && (Number(rol_id) !== 1 || activoFinal === false)) {
        return res.status(400).json({ error: "No puedes quitarte el rol de administrador ni desactivar tu propia cuenta." });
    }

    try {
        const actual = await pool.query(`SELECT rol_id FROM public.usuarios WHERE usuario_id = $1`, [id]);
        if (actual.rows.length === 0) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }
        // Cambiar el rol de/hacia estudiante dejaría la ficha de estudiantes desincronizada
        if (Number(actual.rows[0].rol_id) !== Number(rol_id) &&
            (Number(actual.rows[0].rol_id) === 3 || Number(rol_id) === 3)) {
            return res.status(400).json({
                error: "No se puede cambiar el rol hacia/desde Estudiante. Crea un usuario nuevo con el rol correcto."
            });
        }

        let result;
        if (contrasena && contrasena.trim() !== "") {
            const contrasenaHash = await bcrypt.hash(contrasena, 10);
            result = await pool.query(
                `UPDATE public.usuarios
                 SET nombre_completo = $1, email = $2, rol_id = $3, activo = $4, contrasena_hash = $5
                 WHERE usuario_id = $6
                 RETURNING usuario_id, nombre_completo, email, rol_id, activo`,
                [nombre_completo.trim(), email, rol_id, activoFinal, contrasenaHash, id]
            );
        } else {
            result = await pool.query(
                `UPDATE public.usuarios
                 SET nombre_completo = $1, email = $2, rol_id = $3, activo = $4
                 WHERE usuario_id = $5
                 RETURNING usuario_id, nombre_completo, email, rol_id, activo`,
                [nombre_completo.trim(), email, rol_id, activoFinal, id]
            );
        }

        // Mantener sincronizado el correo de la ficha de estudiante
        if (Number(rol_id) === 3) {
            await pool.query(`UPDATE public.estudiantes SET email = $1 WHERE estudiante_id = $2`, [email, id]);
        }

        res.json({ message: "Usuario actualizado correctamente.", usuario: result.rows[0] });

    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ error: "Ya existe otro usuario con ese correo electrónico." });
        }
        console.error("🔴 Error al actualizar usuario:", error);
        res.status(500).json({ error: "Error interno al actualizar el usuario." });
    }
}


// 5. Eliminar Usuario (baja lógica: activo = false)
async function desactivarUsuario(req, res) {
    const { id } = req.params;

    if (String(id) === String(req.user.id)) {
        return res.status(400).json({ error: "No puedes desactivar tu propia cuenta." });
    }

    try {
        const result = await pool.query(
            `UPDATE public.usuarios
             SET activo = false
             WHERE usuario_id = $1 RETURNING *`,
            [id]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: "Usuario no encontrado." });

        res.json({
            message: "Usuario desactivado.",
            usuario: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al desactivar usuario:", error);
        res.status(500).json({ error: "Error interno al cambiar estado del usuario." });
    }
}

/* ============================================================
   6. GET /api/usuarios/mi-perfil  (cualquier usuario autenticado,
   consulta SUS PROPIOS datos — no requiere ser Admin)
   Si es Docente (rol_id 2), además trae estadísticas reales:
   grupos a cargo, estudiantes totales, recetas creadas y las
   asignaturas que imparte.
   ============================================================ */
async function obtenerMiPerfil(req, res) {
    try {
        const result = await pool.query(
            `SELECT usuario_id, nombre_completo, email, rol_id, activo
             FROM public.usuarios
             WHERE usuario_id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }

        const usuario = result.rows[0];
        let stats = null;

        if (usuario.rol_id === 2) {
            const [grupos, estudiantes, recetas, asignaturas] = await Promise.all([
                pool.query(
                    `SELECT COUNT(*)::int AS total
                     FROM public.horarios_clase
                     WHERE docente_id = $1`,
                    [req.user.id]
                ),
                pool.query(
                    `SELECT COUNT(DISTINCT m.estudiante_id)::int AS total
                     FROM public.matriculas_horario m
                     JOIN public.horarios_clase h ON m.horario_id = h.horario_id
                     WHERE h.docente_id = $1`,
                    [req.user.id]
                ),
                pool.query(
                    `SELECT COUNT(*)::int AS total
                     FROM public.recetas
                     WHERE usuario_creador_id = $1`,
                    [req.user.id]
                ),
                pool.query(
                    `SELECT DISTINCT a.asignatura_id, a.nombre_asignatura
                     FROM public.horarios_clase h
                     JOIN public.asignaturas a ON h.asignatura_id = a.asignatura_id
                     WHERE h.docente_id = $1
                     ORDER BY a.nombre_asignatura`,
                    [req.user.id]
                ),
            ]);

            stats = {
                total_grupos: grupos.rows[0].total,
                total_estudiantes: estudiantes.rows[0].total,
                total_recetas: recetas.rows[0].total,
                asignaturas: asignaturas.rows
            };
        }

        res.json({ usuario, stats });
    } catch (error) {
        console.error("🔴 Error al obtener mi perfil:", error);
        res.status(500).json({ error: "Error al obtener tu perfil." });
    }
}

module.exports = {
    crearUsuario,
    obtenerUsuarios,
    obtenerUsuarioPorId,
    actualizarUsuario,
    desactivarUsuario,
    obtenerMiPerfil
};
