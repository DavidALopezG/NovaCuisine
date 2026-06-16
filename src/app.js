const express = require("express");
const cors = require("cors");
const authRoutes = require("./routes/authRoutes");
const cobrosRoutes = require("./routes/cobrosRoutes");
const { verifyToken, authorizeRoles } = require("./middleware/authMiddleware");

const app = express();

app.use(express.json());
app.use(cors());

// Rutas organizadas
app.use("/api/auth", authRoutes);
app.use("/api/cobros", cobrosRoutes);
app.use("/api/estudiantes", require("./routes/estudiantesRoutes"));
app.use("/api/usuarios", require("./routes/usuariosRoutes"));

app.get("/api/admin", verifyToken, authorizeRoles("Admininstrador"), (req, res) => {
  res.json({ message: "Bienvenido, Admin!" });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
