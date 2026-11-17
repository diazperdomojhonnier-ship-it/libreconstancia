# Historial de cambios

## 0.2.0 — 2026-11-17 (experimental)

- Listas de revocación Ed25519 firmadas, conservando revocaciones previas.
- Comprobación separada de la integridad de la firma y del estado de revocación.
- Aviso explícito cuando la lista de revocaciones está ausente o no es confiable.
- Comando `link` para compartir certificados ya firmados sin usar la clave privada.
- Demostración pública con datos sintéticos y certificados de distinto estado.
- Pruebas de interoperabilidad Python/Node y de la lógica real del navegador.
- Mayor seguridad al escribir QR y limitar permisos de GitHub Actions.

**Compatibilidad:** las constancias con esquema `1` emitidas en 0.1 siguen siendo verificables; el registro de revocaciones es un documento independiente. Quien use el sitio estático debe publicar una lista de revocaciones firmada o aceptar que aparezca «estado no comprobado».

## 0.1.0 — 2026-11-17

- Primer motor para firmar JSON con Ed25519 y generar enlaces/QR.
- Verificador estático, CLI y documentación inicial.

Este proyecto no constituye una certificación académica, revisión legal ni auditoría de seguridad externa.
