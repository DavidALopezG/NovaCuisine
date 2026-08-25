// src/encryptionService.js
const crypto = require("crypto");
const { requireEnv } = require("./config/env");

// La clave ahora viene de .env (antes estaba hardcodeada en el código y subida
// a git). Se mantiene la MISMA derivación (sha256 + base64 + substring) para
// no romper la lectura de datos ya cifrados con la clave anterior, siempre y
// cuando pongas exactamente el mismo texto en ENCRYPTION_KEY que tenías antes
// ("clave_super_secreta_para_AES") — ver .env.example.
const ENCRYPTION_KEY = crypto
  .createHash("sha256")
  .update(String(requireEnv("ENCRYPTION_KEY")))
  .digest("base64")
  .substring(0, 32);

// IV fijo en ceros — SOLO se mantiene para poder descifrar datos viejos ya
// guardados con este esquema roto. Los cifrados NUEVOS ya no lo usan (ver abajo).
const IV_LEGACY_INSEGURO = Buffer.alloc(16, 0);

/**
 * Cifra un texto con un IV aleatorio nuevo en cada llamada (correcto: con
 * AES-CBC, reutilizar el mismo IV para todos los registros hace que textos
 * iguales produzcan siempre el mismo cifrado, revelando patrones). El IV no es
 * secreto, así que se guarda concatenado al inicio del resultado.
 */
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");
  return `${iv.toString("base64")}:${encrypted}`;
}

/**
 * Descifra. Soporta el formato nuevo ("iv:cifrado") y, por compatibilidad,
 * el formato viejo (solo "cifrado", con el IV fijo en cero) para no romper
 * filas que ya existan en usuarios_encriptados de antes de este fix.
 */
function decrypt(encryptedText) {
  const partes = String(encryptedText).split(":");

  if (partes.length === 2) {
    const [ivB64, dataB64] = partes;
    const iv = Buffer.from(ivB64, "base64");
    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(dataB64, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }

  // Formato viejo (dato cifrado antes de este fix)
  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), IV_LEGACY_INSEGURO);
  let decrypted = decipher.update(encryptedText, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

module.exports = { encrypt, decrypt };
