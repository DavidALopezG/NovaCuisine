const pool = require("../db");

// 1. Crear Usuario (solo Admin)
async function crearUsuario(req, res) {
    const { nombre_completo, email, contrasena_hash, rol_id, activo } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO public.usuarios (nombre_completo, email, contrasena_hash, rol_id, activo)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [nombre_completo, email, contrasena_hash, rol_id, activo ?? true]
        );

        res.status(201).json({
            message: "Usuario creado exitosamente.",
            usuario: result.rows[0]
        });

    } catch (error) {
        console.error("🔴 Error al crear usuario:", error);
        res.status(500).json({ error: "Error interno al crear el usuario." });
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
    const { nombre_completo, email, rol_id, activo } = req.body;

    try {
        const result = await pool.query(
            `UPDATE public.usuarios
             SET nombre_completo = $1,
                 email = $2,
                 rol_id = $3,
                 activo = $4
             WHERE usuario_id = $5
             RETURNING *`,
            [nombre_completo, email, rol_id, activo, id]
        );

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
