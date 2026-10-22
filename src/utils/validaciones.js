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

/**
 * Convierte a centavos (entero) o devuelve null si no es un monto válido (> 0, máx. 2 decimales).
 * Solo acepta number o string decimal simple ("12", "12.5", "12.50"): se rechazan booleanos,
 * arreglos, notación científica ("1e2") y espacios, que Number() convertiría sin error.
 */
function aCentavos(valor, maximo = 100000) {
    if (typeof valor === "string") {
        if (!/^\d+(\.\d{1,2})?$/.test(valor.trim())) return null;
    } else if (typeof valor !== "number") {
        return null;
    }
    const n = Number(valor);
    if (!Number.isFinite(n) || n <= 0 || n > maximo) return null;
    const centavos = Math.round(n * 100);
    if (Math.abs(centavos / 100 - n) > 1e-9) return null; // más de 2 decimales
    return centavos;
}

/** Texto con longitud entre min y max (después de recortar espacios). */
function textoEnRango(valor, min, max) {
    const t = String(valor ?? "").trim();
    return t.length >= min && t.length <= max;
}

/**
 * Número finito dentro de un rango. Rechaza vacío, null, booleanos y texto no numérico.
 * Opciones: { min, max, minExclusivo } (minExclusivo: true => el valor debe ser > min).
 */
function numeroEnRango(valor, { min = -Infinity, max = Infinity, minExclusivo = false } = {}) {
    if (valor === null || valor === undefined || valor === "" || typeof valor === "boolean") return false;
    const n = Number(valor);
    if (!Number.isFinite(n)) return false;
    if (minExclusivo ? n <= min : n < min) return false;
    return n <= max;
}

/** Entero mayor a 0 (sirve para validar ids que llegan por body o por URL). */
function enteroPositivo(valor) {
    if (valor === null || valor === undefined || valor === "" || typeof valor === "boolean") return false;
    const n = Number(valor);
    return Number.isInteger(n) && n > 0;
}

function esHoraValida(h) {
    return /^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/.test(String(h || ""));
}


/** Fecha local de hoy en formato YYYY-MM-DD (sin pasar por UTC). */
function hoyISO() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/**
 * Normaliza una fecha a "YYYY-MM-DD" REAL (rechaza 2026-02-31) sin desfases de zona horaria.
 * Acepta "YYYY-MM-DD" (con o sin hora) y objetos Date (p. ej. celdas de Excel, tomadas en hora local).
 */
function fechaISOValida(valor) {
    let y, m, d;
    if (valor instanceof Date) {
        if (Number.isNaN(valor.getTime())) return null;
        y = valor.getFullYear(); m = valor.getMonth() + 1; d = valor.getDate();
    } else {
        const x = /^(\d{4})-(\d{2})-(\d{2})(?:$|[T ])/.exec(String(valor ?? "").trim());
        if (!x) return null;
        y = Number(x[1]); m = Number(x[2]); d = Number(x[3]);
    }
    const t = new Date(Date.UTC(y, m - 1, d));
    if (t.getUTCFullYear() !== y || t.getUTCMonth() !== m - 1 || t.getUTCDate() !== d) return null;
    return `${String(y).padStart(4, "0")}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

/** Middleware para router.param: el id de la ruta debe ser un entero positivo (si no, 400 en vez de 500). */
function validarIdParam(req, res, next, valor) {
    if (!/^\d{1,9}$/.test(String(valor)) || Number(valor) < 1) {
        return res.status(400).json({ error: "El identificador de la ruta no es válido." });
    }
    next();
}

const DIAS_VALIDOS = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"];

module.exports = {
    normalizarEmail,
    emailValido,
    cedulaEcuatorianaValida,
    contrasenaValida,
    aCentavos,
    textoEnRango,
    numeroEnRango,
    enteroPositivo,
    hoyISO,
    fechaISOValida,
    validarIdParam,
    esHoraValida,
    DIAS_VALIDOS
};
