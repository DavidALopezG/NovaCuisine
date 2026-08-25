// src/config/env.js
// Exige que ciertas variables de entorno existan antes de arrancar el servidor.
// Antes, secretos reales (contraseña de BD, JWT secret, clave de cifrado) tenían
// un valor por defecto hardcodeado en el código fuente y subido a git. Con esto,
// si falta la variable en tu .env, el servidor se detiene con un mensaje claro
// en vez de arrancar silenciosamente con un secreto expuesto en el repositorio.
function requireEnv(name) {
  const valor = process.env[name];
  if (!valor) {
    console.error(
      `🔴 Falta la variable de entorno "${name}". Defínela en tu archivo .env local ` +
      `(revisa .env.example) — nunca subas el .env real a git.`
    );
    process.exit(1);
  }
  return valor;
}

module.exports = { requireEnv };
