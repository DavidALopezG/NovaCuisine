const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("./db");
const authRoutes = require("./routes/authRoutes");
const cobrosRoutes = require("./routes/cobrosRoutes");
const { verifyToken, authorizeRoles } = require("./middleware/authMiddleware");
const { encrypt, decrypt } = require("./encryptionService");
const app = express();
app.use(express.json());
const cors = require("cors");
app.use(cors());
app.use("/api/auth", authRoutes);
app.use("/api/cobros", cobrosRoutes);

// 📩 Crear usuario y guardar en ambas tablas
app.post("/api/usuarios", async (req, res) => {
  const { nombre_completo, usuario_id, email, contrasena,rol_id,activo } = req.body;

  try {
    // 🔑 Hashear la contraseña (bcrypt)
    const contrasenaHash = await bcrypt.hash(contrasena, 10);

    // Guardar usuario con contraseña hasheada en tabla USUARIO
    const result = await pool.query(
      `INSERT INTO usuarios (usuario_id, nombre_completo, email, contrasena_hash, rol_id, activo)
       VALUES ($1, $2, $3, $4, $5,$6) RETURNING usuario_id`,
      [usuario_id, nombre_completo, email, contrasenaHash, rol_id, activo]
    );


    const usuarioId = result.rows[0].usuario_id;
    const fecha_registro = new Date();

    // Guardar versión encriptada de los datos (excepto contraseña)
    await pool.query(
      `INSERT INTO public.usuarios_encriptados (usuario_id, nombre_encriptado, email_encriptado,fecha_registro)
       VALUES ($1, $2, $3, $4)`,
      [
        usuario_id,
        encrypt(nombre_completo),
        encrypt(email),
        fecha_registro
      ]
    );


    res.status(201).json({ message: "Usuario creado correctamente con hash y datos encriptados." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al crear el usuario." });
  }
});

// 📤 Obtener usuarios (sin mostrar contraseña)
app.get("/api/usuarios", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM usuarios_encriptados");

    const usuarios = result.rows.map((row) => ({
      usuario_encriptado_id: row.usuario_enc_id,
      nombre_encriptado: decrypt(row.nombre_encriptado),
      usuario_id: row.usuario_id,
      email_encriptado: decrypt(row.email_encriptado),
      fecha_registro: row.fecha_registro
      // contraseña nunca se muestra
    }));

    res.json(usuarios);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener usuarios." });
  }
});

app.get("/api/admin", verifyToken, authorizeRoles("Admininstrador"), (req, res) => {
  res.json({ message: "Bienvenido, Admin!" });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
