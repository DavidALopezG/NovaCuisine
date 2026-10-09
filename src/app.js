const express = require("express");
const cors = require("cors");
const path = require("path");
const authRoutes = require("./routes/authRoutes");
const cobrosRoutes = require("./routes/cobrosRoutes");
const { verifyToken, authorizeRoles } = require("./middleware/authMiddleware");

const app = express();

app.use(express.json());
app.use(cors());

// Sirve fotos de estudiante y comprobantes de pago subidos vía multer
// (diskStorage en src/middleware/uploadArchivos.js). Requiere sesión iniciada
// en el frontend para llegar a esta URL, pero el archivo en sí no exige token
// porque <img>/<a> del navegador no pueden enviar Authorization header.
app.use("/uploads", express.static(path.join(__dirname, "..", "uploads")));

// Rutas organizadas
app.use("/api/auth", authRoutes);
app.use("/api/cobros", cobrosRoutes);
app.use("/api/estudiantes", require("./routes/estudiantesRoutes"));
app.use("/api/usuarios", require("./routes/usuariosRoutes"));
app.use("/api/recetas", require("./routes/recetasRoutes"));
app.use("/api/asignaturas", require("./routes/asignaturasRoutes"));
app.use("/api/insumos", require("./routes/insumosRoutes"));
app.use("/api/horarios", require("./routes/horariosRoutes"));
app.use("/api/titulaciones", require("./routes/titulacionesRoutes"));
app.use("/api/reportes", require("./routes/reportesRoutes"));

app.get("/api/admin", verifyToken, authorizeRoles("Admininstrador"), (req, res) => {
  res.json({ message: "Bienvenido, Admin!" });
});

// Manejador de errores centralizado — sin esto, un error de multer (archivo muy
// grande o de tipo no permitido) o cualquier excepción no controlada devolvía
// una página HTML de error en vez de JSON, y el frontend no podía mostrar
// el mensaje real en el toast (esperaba siempre { error: "..." }).
app.use((err, req, res, next) => {
  console.error("🔴 Error no controlado:", err.message);
  if (err.name === "MulterError" || err.message?.includes("Excel") || err.message?.includes("imagen") || err.message?.includes("comprobante") || err.message?.includes("PDF")) {
    return res.status(400).json({ error: err.message });
  }
  res.status(500).json({ error: "Ocurrió un error interno en el servidor." });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));

// Recargos por mora: al arrancar y luego cada 6 horas (idempotente; si está desactivado no hace nada).
const { aplicarRecargos } = require("./utils/cobrosCore");
const correrRecargos = async () => {
  try {
    const r = await aplicarRecargos();
    if (r.cuotas > 0) console.log(`💲 Recargos aplicados: ${r.cuotas} cuota(s), $${r.total.toFixed(2)}`);
  } catch (e) {
    if (e.code !== "42P01" && e.code !== "42703") console.error("⚠️ Job de recargos:", e.message);
  }
};
setTimeout(correrRecargos, 15 * 1000);
setInterval(correrRecargos, 6 * 60 * 60 * 1000);
