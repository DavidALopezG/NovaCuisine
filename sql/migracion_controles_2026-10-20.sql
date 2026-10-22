-- migracion_controles_2026-10-20.sql
-- Restricciones CHECK como "segunda línea de defensa": aunque alguien salte el backend (Postman, script, SQL manual),
-- la base de datos rechaza montos negativos o incoherentes. Idempotente: se puede ejecutar varias veces.
-- Se crean NOT VALID: se aplican a TODO dato nuevo sin fallar si ya hubiera filas antiguas incorrectas.
-- Para revisar las filas viejas:  SELECT * FROM public.insumos_costos WHERE costo_unitario < 0;  (etc.)
-- Cuando estén corregidas:        ALTER TABLE ... VALIDATE CONSTRAINT <nombre>;

DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    ('insumos_costos',          'chk_insumo_costo_no_negativo',   'costo_unitario >= 0'),
    ('receta_version_insumos',  'chk_rvi_cantidad_no_negativa',   'cantidad >= 0'),
    ('receta_articulos_menaje', 'chk_menaje_cantidad_positiva',   'cantidad_requerida > 0'),
    ('recetas_versiones',       'chk_version_precio_no_negativo', 'precio_venta_sugerido IS NULL OR precio_venta_sugerido >= 0'),
    ('recetas',                 'chk_receta_porciones',           'porciones BETWEEN 1 AND 500'),
    ('cobros_obligaciones',     'chk_obl_montos_validos',         'monto_total >= 0 AND monto_pagado >= 0 AND recargo_acumulado >= 0'),
    ('cobros_obligaciones',     'chk_obl_pagado_no_excede_total', 'monto_pagado <= monto_total'),
    ('cobros_pagos',            'chk_pago_monto_positivo',        'monto > 0')
  ) AS t(tabla, nombre, condicion)
  LOOP
    IF to_regclass('public.' || r.tabla) IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = r.nombre) THEN
      EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (%s) NOT VALID', r.tabla, r.nombre, r.condicion);
      RAISE NOTICE 'Restricción creada: %', r.nombre;
    END IF;
  END LOOP;
END $$;
