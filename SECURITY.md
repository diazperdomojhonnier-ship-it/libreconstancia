# Seguridad

## Modelo de confianza

- **La clave privada del emisor es el secreto principal.** Se almacena cifrada y debe estar bajo control de su titular. Si se pierde, no puede reconstruirse.
- **La clave pública debe llegar desde un sitio auténtico del emisor.** El algoritmo verifica una firma, no la reputación de una escuela.
- **El verificador estático consulta un registro local de claves reconocidas.** Si se compromete el alojamiento o se suplanta su dominio, pueden mostrarse verificaciones engañosas.
- **Los QR contienen datos personales legibles.** Su inclusión debe respetar el consentimiento, finalidad y obligaciones de protección de datos del emisor.
- **No existe revocación en v0.1.** Los certificados firmados pueden seguir apareciendo válidos aunque administrativamente hayan sido anulados. No usar cuando se requiera consultar estado vigente.
- **No se garantiza validez jurídica o académica.** La herramienta solo verifica integridad y firma con Ed25519.

## Reporte responsable

Si encuentras una vulnerabilidad, no publiques claves ni datos reales. Al abrir el repositorio en GitHub, activa *Private vulnerability reporting* o una conversación privada con el responsable antes de divulgar detalles explotables.

## Producción

Mantén actualizado Python y `cryptography`; publica el verificador solamente bajo HTTPS; haz respaldos seguros de las claves privadas; no utilices la clave privada en equipos compartidos ni en repositorios públicos. La versión actual necesita auditoría externa antes de adoptarse para documentos críticos.
