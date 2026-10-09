// src/middleware/limitarIntentos.js
// Limitador de intentos en memoria (sin dependencias externas).
// Suficiente para un solo proceso Node; si se escala a varios, usar Redis/express-rate-limit.
function limitarIntentos({ maxIntentos = 10, ventanaMs = 15 * 60 * 1000, clave }) {
    const registro = new Map();

    // Limpieza periódica para que el Map no crezca indefinidamente
    setInterval(() => {
        const ahora = Date.now();
        for (const [k, v] of registro) if (v.reinicio <= ahora) registro.delete(k);
    }, ventanaMs).unref();

    return (req, res, next) => {
        const k = clave(req);
        const ahora = Date.now();
        let entrada = registro.get(k);
        if (!entrada || entrada.reinicio <= ahora) {
            entrada = { cuenta: 0, reinicio: ahora + ventanaMs };
            registro.set(k, entrada);
        }
        entrada.cuenta++;
        if (entrada.cuenta > maxIntentos) {
            const segundos = Math.ceil((entrada.reinicio - ahora) / 1000);
            res.set("Retry-After", String(segundos));
            return res.status(429).json({
                error: `Demasiados intentos. Vuelve a intentarlo en ${Math.ceil(segundos / 60)} minuto(s).`
            });
        }
        next();
    };
}

module.exports = { limitarIntentos };
