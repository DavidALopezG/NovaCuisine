const crypto = require("crypto");

const ENCRYPTION_KEY = crypto
  .createHash("sha256")
  .update(String("clave_super_secreta_para_AES"))
  .digest("base64")
  .substring(0, 32); // 32 bytes para AES-256
const IV = Buffer.alloc(16, 0);

function encrypt(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), IV);
  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function decrypt(encryptedText) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), IV);
  let decrypted = decipher.update(encryptedText, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

module.exports = { encrypt, decrypt };
