// src/utils/validaciones.js
// Validaciones reutilizables para controladores (formato, rangos, dinero).

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function normalizarEmail(email) {
    return String(email || "").trim().toLowerCase();
}

function emailValido(email) {
    const e = normalizarEmail(email);
    return e.length <= 120 && EMAIL_REGEX.test(e);
}

/** Cédula ecuatoriana: 10 dígitos, provincia 01-24 (o 30), 3er dígito < 6, módulo 10. */
function cedulaEcuatorianaValida(cedula) {
    const c = String(cedula || "").trim();
    if (!/^\d{10}$/.test(c)) return false;

    const provincia = parseInt(c.slice(0, 2), 10);
    if (!((provincia >= 1 && provincia <= 24) || provincia === 30)) return false;
    if (parseInt(c[2], 10) >= 6) return false;

    let suma = 0;
    for (let i = 0; i < 9; i++) {
        let d = parseInt(c[i], 10) * (i % 2 === 0 ? 2 : 1);
        if (d > 9) d -= 9;
        suma += d;
    }
    const verificador = (10 - (suma % 10)) % 10;
    return verificador === parseInt(c[9], 10);
}

/** Mínimo 8 caracteres, al menos una letra y un número. */
function contrasenaValida(pwd) {
    const p = String(pwd || "");
    return p.length >= 8 && p.length <= 72 && /[A-Za-z]/.test(p) && /\d/.test(p);
}

/** Convierte a centavos (entero) o devuelve null si no es un monto válido (> 0, máx. 2 decimales). */
function aCentavos(valor, maximo = 100000) {
    const n = Number(valor);
    if (!Number.isFinite(n) || n <= 0 || n > maximo) return null;
    const centavos = Math.round(n * 100);
    if (Math.abs(centavos / 100 - n) > 1e-9) return null; // más de 2 decimales
    return centavos;
}

function esHoraValida(h) {
    return /^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/.test(String(h || ""));
}

const DIAS_VALIDOS = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"];

module.exports = {
    normalizarEmail,
    emailValido,
    cedulaEcuatorianaValida,
    contrasenaValida,
    aCentavos,
    esHoraValida,
    DIAS_VALIDOS
};
