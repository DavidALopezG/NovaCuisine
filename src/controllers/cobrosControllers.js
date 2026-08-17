// backend/controllers/cobros.controllers.js
const pool = require("../db");
const XLSX = require("xlsx");

// Función auxiliar para calcular la fecha de vencimiento (3 meses a partir de hoy)
const calcularFechaVencimiento = () => {
    const today = new Date();
    // Suma 3 meses a la fecha actual
    today.setMonth(today.getMonth() + 3); 
    // PostgreSQL acepta objetos Date directamente
    return today; 
};

// 1. POST: Crear una Nueva Obligación (CREATE)
async function crearObligacion(req, res) {
    // Solo el Administrador debe poder crear obligaciones
    const { estudiante_id, monto_total } = req.body;
    
    // Valores por defecto
    const monto_pagado = 0.00;
    const estado = 'Pendiente'; 
    const fecha_vencimiento = calcularFechaVencimiento();
    // La fecha_pago se establece en NULL hasta que se registre un pago.

    try {
        const result = await pool.query(
            `INSERT INTO public.cobros_obligaciones (estudiante_id, fecha_vencimiento, monto_total, monto_pagado, estado)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [estudiante_id, fecha_vencimiento, monto_total, monto_pagado, estado]
        );

        res.status(201).json({ 
            message: "Obligación creada con vencimiento a 3 meses.", 
            obligacion: result.rows[0] 
        });

    } catch (error) {
        console.error("🔴 Error al crear obligación:", error);
        res.status(500).json({ error: "Error interno al crear la obligación." });
    }
}


// 2. GET: Obtener Todas las Obligaciones (READ All)
async function obtenerObligaciones(req, res) {
    try {
        const result = await pool.query(
            `SELECT * FROM public.cobros_obligaciones ORDER BY fecha_vencimiento ASC`
        );
        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener obligaciones:", error);
        res.status(500).json({ error: "Error al obtener obligaciones." });
    }
}

// 3. PUT: Registrar Pago y Actualizar Obligación (UPDATE)
async function registrarPago(req, res) {
    // ⚠️ Esta función asume que solo se realiza un pago a la vez para una obligación.
    const { obligacion_id, monto_pago } = req.body;
    const fecha_pago = new Date(); // Fecha del registro del pago

    try {
        // Inicia una transacción para asegurar atomicidad
        await pool.query('BEGIN'); 

        // 1. Obtener el estado actual de la obligación
        const obligacionResult = await pool.query(
            `SELECT monto_total, monto_pagado, estado FROM public.cobros_obligaciones WHERE obligacion_id = $1`,
            [obligacion_id]
        );

        if (obligacionResult.rows.length === 0) {
            await pool.query('ROLLBACK');
            return res.status(404).json({ error: "Obligación no encontrada." });
        }
        
        const obligacion = obligacionResult.rows[0];
        const nuevoMontoPagado = parseFloat(obligacion.monto_pagado) + parseFloat(monto_pago);
        const montoPendiente = parseFloat(obligacion.monto_total) - nuevoMontoPagado;

        if (montoPendiente < 0) {
            await pool.query('ROLLBACK');
            return res.status(400).json({ error: "El monto del pago excede la deuda restante." });
        }

        const nuevoEstado = montoPendiente === 0 ? 'Pagado' : 'Parcial';

        // 2. Actualizar la obligación con el nuevo monto, estado y fecha de pago.
        const updateResult = await pool.query(
            `UPDATE public.cobros_obligaciones
             SET monto_pagado = $1, 
                 estado = $2,
                 fecha_pago = $3
             WHERE obligacion_id = $4 RETURNING *`,
            [nuevoMontoPagado, nuevoEstado, fecha_pago, obligacion_id]
        );

        // 3. Confirmar la transacción
        await pool.query('COMMIT');
        
        // ✅ PRUEBAS DE ACEPTACIÓN: El administrador registra un pago y la BD refleja el cambio
        res.json({
            message: "Pago registrado y obligación actualizada.",
            obligacion_actualizada: updateResult.rows[0],
            estado_anterior: obligacion.estado
        });

    } catch (error) {
        await pool.query('ROLLBACK'); // Revertir si algo falla
        console.error("🔴 Error en la transacción de pago:", error);
        res.status(500).json({ error: "Error interno al procesar el pago y la deuda." });
    }
}

// 4. POST: Importar Obligaciones masivamente desde un archivo Excel
//    Columnas esperadas en la hoja (primera fila = encabezados):
//    estudiante_id | monto_total | fecha_vencimiento (opcional, formato AAAA-MM-DD)
async function importarObligacionesExcel(req, res) {
    if (!req.file) {
        return res.status(400).json({ error: "Debes adjuntar un archivo Excel (.xlsx o .xls)." });
    }

    let filas;
    try {
        const workbook = XLSX.read(req.file.buffer, { type: "buffer" });
        const primeraHoja = workbook.SheetNames[0];
        filas = XLSX.utils.sheet_to_json(workbook.Sheets[primeraHoja], { defval: null });
    } catch (error) {
        console.error("🔴 Error al leer el archivo Excel:", error);
        return res.status(400).json({ error: "No se pudo leer el archivo. Verifica que sea un Excel válido." });
    }

    if (filas.length === 0) {
        return res.status(400).json({ error: "El archivo no contiene filas de datos." });
    }

    const insertadas = [];
    const errores = [];
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        for (let i = 0; i < filas.length; i++) {
            const fila = filas[i];
            const numeroFila = i + 2; // +2 porque la fila 1 es el encabezado

            // Normaliza nombres de columna (acepta mayúsculas/minúsculas y espacios)
            const claves = Object.keys(fila).reduce((acc, key) => {
                acc[key.toString().trim().toLowerCase()] = fila[key];
                return acc;
            }, {});

            const estudiante_id = claves["estudiante_id"];
            const monto_total = claves["monto_total"];
            const fecha_vencimiento_raw = claves["fecha_vencimiento"];

            if (!estudiante_id || monto_total === null || monto_total === undefined || isNaN(Number(monto_total))) {
                errores.push({ fila: numeroFila, motivo: "estudiante_id o monto_total faltante/ inválido." });
                continue;
            }

            const fecha_vencimiento = fecha_vencimiento_raw
                ? new Date(fecha_vencimiento_raw)
                : calcularFechaVencimiento();

            try {
                const result = await client.query(
                    `INSERT INTO public.cobros_obligaciones (estudiante_id, fecha_vencimiento, monto_total, monto_pagado, estado)
                     VALUES ($1, $2, $3, 0.00, 'Pendiente') RETURNING *`,
                    [String(estudiante_id), fecha_vencimiento, Number(monto_total)]
                );
                insertadas.push(result.rows[0]);
            } catch (errorFila) {
                errores.push({ fila: numeroFila, motivo: errorFila.message });
            }
        }

        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        console.error("🔴 Error en la importación masiva:", error);
        return res.status(500).json({ error: "Error interno durante la importación." });
    } finally {
        client.release();
    }

    res.status(201).json({
        message: `Importación finalizada: ${insertadas.length} obligaciones creadas, ${errores.length} filas con error.`,
        total_filas: filas.length,
        insertadas,
        errores
    });
}

// 4. GET: Estado de cuenta del estudiante autenticado (usa la vista VISTA_ESTADO_COBROS)
async function obtenerMisObligaciones(req, res) {
    try {
        const estudiante_id = req.user.id;

        const result = await pool.query(
            `SELECT * FROM public.vista_estado_cobros
             WHERE estudiante_id = $1
             ORDER BY fecha_vencimiento ASC`,
            [estudiante_id]
        );

        res.json(result.rows);
    } catch (error) {
        console.error("🔴 Error al obtener el estado de cuenta del estudiante:", error);
        res.status(500).json({ error: "Error al obtener tu estado de cuenta." });
    }
}

module.exports = {
    crearObligacion,
    obtenerObligaciones,
    registrarPago,
    importarObligacionesExcel,
    obtenerMisObligaciones
    // Aquí puedes añadir más funciones CRUD (e.g., obtener por estudiante, eliminar)
};