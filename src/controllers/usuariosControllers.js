const pool = require("../db");
const bcrypt = require("bcrypt");

// 1. Crear Usuario (solo Admin)
async function crearUsuario(req, res) {
    const { usuario_id, nombre_completo, email, contrasena, rol_id, activo, titulacion_id } = req.body;

    if (!usuario_id || !nombre_completo || !email || !contrasena || !rol_id) {
        return res.status(400).json({
            error: "usuario_id, nombre_completo, email, contrasena y rol_id son obligatorios."
        });
    }

    const client = await pool.connect();
    try {
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
            const partes = nombre_completo.trim().split(" ");
            const nombre = partes[0];
            const apellido = partes.slice(1).join(" ") || " ";
            const codigoEstudiante = `EST-${Date.now().toString().slice(-5)}`;

            await client.query(
                `INSERT INTO public.estudiantes
                    (estudiante_id, nombre, apellido, email, titulacion_id, fecha_ingreso, codigo_estudiante)
                 VALUES ($1, $2, $3, $4, $5, NOW(), $6)`,
                [usuario_id, nombre, apellido, email, titulacion_id || 1, codigoEstudiante]
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
            if (error.detail && error.detail.toLowerCase().includes("email")) {
                return res.status(409).json({ error: "Ya existe un usuario con ese correo electrónico." });
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
    const { nombre_completo, email, rol_id, activo, contrasena } = req.body;

    try {
        let result;

        if (contrasena && contrasena.trim() !== "") {
            // Se incluyó una nueva contraseña: también se actualiza el hash
            const contrasenaHash = await bcrypt.hash(contrasena, 10);
            result = await pool.query(
                `UPDATE public.usuarios
                 SET nombre_completo = $1,
                     email = $2,
                     rol_id = $3,
                     activo = $4,
                     contrasena_hash = $5
                 WHERE usuario_id = $6
                 RETURNING usuario_id, nombre_completo, email, rol_id, activo`,
                [nombre_completo, email, rol_id, activo, contrasenaHash, id]
            );
        } else {
            result = await pool.query(
                `UPDATE public.usuarios
                 SET nombre_completo = $1,
                     email = $2,
                     rol_id = $3,
                     activo = $4
                 WHERE usuario_id = $5
                 RETURNING usuario_id, nombre_completo, email, rol_id, activo`,
                [nombre_completo, email, rol_id, activo, id]
            );
        }

        if (result.rows.length === 0)
            return res.status(404).json({ error: "Usuario no encontrado." });

        res.json({
            message: "Usuario actualizado correctamente.",
            usuario: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al actualizar usuario:", error);
        res.status(500).json({ error: "Error interno al actualizar el usuario." });
    }
}


// 5. Eliminar Usuario (baja lógica: activo = false)
async function desactivarUsuario(req, res) {
    const { id } = req.params;

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

module.exports = {
    crearUsuario,
    obtenerUsuarios,
    obtenerUsuarioPorId,
    actualizarUsuario,
    desactivarUsuario
};
