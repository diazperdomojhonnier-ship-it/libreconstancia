# LibreConstancia

**Constancias educativas firmadas, verificables y sin dependencia de plataformas comerciales.**

LibreConstancia es una herramienta abierta para organizaciones educativas, colectivos comunitarios y proyectos de formación. Permite generar constancias en formato JSON, firmarlas con Ed25519, comprobar que no fueron alteradas y crear códigos QR que abren un verificador web estático. El código funciona sin cuentas, servidores de pago, bases de datos ni servicios de terceros.

**Estado:** versión experimental funcional (MVP 0.2). Incluye revocaciones firmadas. Todavía no es un sistema integral de matrícula, pagos, PDF o administración educativa.

## ¿Qué problema resuelve?

Muchos cursos, talleres y organizaciones pequeñas necesitan una manera simple de demostrar que una constancia fue emitida por ellos y no modificada después. LibreConstancia separa dos cosas:

- **Integridad criptográfica:** la firma valida que la información no cambió y que se utilizó la clave del emisor.
- **Reconocimiento institucional o legal:** no lo otorga el programa; depende de la entidad emisora y la normativa aplicable.

## Instalación

Necesitas Python 3.10 o superior:

```bash
python -m pip install -e '.[qr]'
```

Si solo deseas firmar/verificar JSON sin generar imágenes QR: `python -m pip install -e .`.

## Prueba completa en cinco pasos

1. **Crear las claves de tu entidad** (el programa pide una contraseña de al menos 12 caracteres):

   ```bash
   libreconstancia keygen --output private-keys
   ```

   Nunca subas `private-keys/private.pem` a GitHub ni lo compartas. Conserva una copia segura.

2. **Preparar el verificador web y una lista firmada de revocaciones**:

   ```bash
   libreconstancia revocations \
     --private-key private-keys/private.pem \
     --output revocations-initial.json
   libreconstancia publish \
     --public-key private-keys/public.json \
     --revocations revocations-initial.json \
     --output public
   python -m http.server 8000 --directory public
   ```

   Para uso real, publica los tres archivos de `public/` en un dominio auténtico bajo **HTTPS**. El servidor local anterior es solo una demostración.

3. **Emitir una constancia de ejemplo** (en otra terminal):

   ```bash
   libreconstancia issue \
     --private-key private-keys/private.pem \
     --issuer "Centro Comunitario de Ejemplo" \
     --participant "Persona de Ejemplo" \
     --program "Lectura crítica" \
     --hours 80 \
     --output constancia.json \
     --verify-url "http://localhost:8000/index.html" \
     --qr constancia-qr.png
   ```

   El comando produce un documento firmado y una imagen QR que dirige al verificador. Su nombre es ficticio, y puedes cambiarlo.

4. **Verificar sin Internet**, usando la clave pública oficial y el registro firmado:

   ```bash
   libreconstancia verify \
     --certificate constancia.json \
     --public-key private-keys/public.json \
     --revocations revocations-initial.json
   ```

5. **Verificar en el navegador:** visita la dirección que imprimió `issue` o escanea `constancia-qr.png`. La página diferencia firma válida, constancia revocada y estado de revocación desconocido. Si se altera cualquier campo firmado, la comprobación falla.

## Revocar una constancia

Si una entidad decide anular una constancia, debe generar un **nuevo archivo firmado** que conserve las revocaciones anteriores:

```bash
libreconstancia revocations \
  --private-key private-keys/private.pem \
  --previous revocations-initial.json \
  --revoke "UUID-DE-LA-CONSTANCIA" \
  --output revocations-actualizadas.json
```

Para actualizar el sitio, ejecuta `publish` en **otra carpeta vacía**, esta vez con `--revocations revocations-actualizadas.json`, y despliega sus archivos en tu alojamiento HTTPS. No sobrescribas tus archivos históricos de revocaciones: consérvalos como respaldo.

**Importante:** una lista firmada demuestra que el emisor publicó ese estado en la fecha indicada, pero no garantiza que sea la última versión. Una firma válida tampoco implica que la constancia siga vigente. Si no se encuentra una lista confiable, la web muestra una advertencia en lugar de afirmar que no está revocada.

Para hacer una prueba inmediata sin generar claves, consulta los ejemplos públicos en [`examples/demo/`](examples/demo/README.md), creados con datos ficticios.

### Demostración interactiva

El directorio `docs/` contiene un sitio estático reproducible con dos botones: una constancia firmada no revocada y otra con firma válida pero **revocada**. Puedes probarlo en tu computador sin crear claves ni instalar dependencias Python:

```bash
python -m http.server 8000 --directory docs
```

Abre `http://localhost:8000` y selecciona un ejemplo. Para comprobar que la versión publicada coincide con el código y los ejemplos, ejecuta `python tools/build_demo_site.py --check`. Para regenerarla tras cambios autorizados: `python tools/build_demo_site.py`. La demostración utiliza exclusivamente entidades y participantes ficticios.

## Qué contiene el proyecto

| Componente | Uso |
| --- | --- |
| `keygen` | Crea una clave privada cifrada y su clave pública |
| `issue` | Firma datos de una constancia y genera un enlace/QR opcional |
| `link` | Genera enlace/QR de un JSON ya firmado, sin necesitar clave privada |
| `verify` | Comprueba el documento contra una clave pública previamente confiable |
| `publish` | Genera un sitio web estático de verificación, sin backend |
| `revocations` | Crea o amplía listas firmadas de certificados revocados |
| `tests/` | Pruebas para firmas válidas, manipulación, claves diferentes y errores |

## Seguridad y privacidad

- La clave privada nunca se copia al verificador público y siempre se almacena cifrada con contraseña.
- Una constancia firmada debe verificarse con la **clave pública obtenida del emisor por una vía confiable**. Un documento no puede demostrar por sí mismo quién controla una institución.
- El QR incluye la información de la constancia **en texto codificado, no cifrado**. Si alguien obtiene el QR podrá leer el nombre, el curso y demás datos. No coloques datos sensibles ni lo publiques sin autorización.
- El contenido del QR viaja en el fragmento `#c=`; el navegador no envía ese fragmento al servidor HTTP. El verificador no tiene analíticas ni scripts de terceros.
- La lista de revocaciones **sí está firmada**, pero puede estar desactualizada o ser sustituida por una versión anterior válida. Comprueba la fecha del registro y controla el alojamiento.
- Sin un registro firmado disponible, el estado administrativo de una constancia se indica como **desconocido**, aunque su firma criptográfica sea válida.
- Un sitio falso podría instalar su propia clave y mostrar una verificación engañosa. Comprueba siempre el dominio del emisor.
- La autenticidad técnica no demuestra asistencia, calidad educativa ni aprobación gubernamental.

Consulta [SECURITY.md](SECURITY.md) para limitaciones y reportes de vulnerabilidades.

## Hoja de ruta abierta

En [ROADMAP.md](ROADMAP.md) están las prioridades: revocación verificable, descarga de PDF, integración con Moodle y WordPress, y pruebas de interoperabilidad. Se aceptan aportes, traducciones y reportes de problemas.

## Participar

Consulta [CONTRIBUTING.md](CONTRIBUTING.md), las [normas de convivencia](CODE_OF_CONDUCT.md) y el [historial de versiones](CHANGELOG.md). No necesitamos clientes de pago ni registros para colaborar. Publica problemas reproducibles, ejemplos o mejoras para entidades pequeñas.

## Licencia

MIT. Consulta [LICENSE](LICENSE). Autor inicial: Jhonnier Díaz Perdomo, Colombia.
