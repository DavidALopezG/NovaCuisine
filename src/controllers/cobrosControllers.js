// backend/controllers/cobros.controllers.js
const pool = require("../db");

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

module.exports = {
    crearObligacion,
    obtenerObligaciones,
    registrarPago
    // Aquí puedes añadir más funciones CRUD (e.g., obtener por estudiante, eliminar)
};