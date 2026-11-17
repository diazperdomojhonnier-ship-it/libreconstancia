# LibreConstancia

**Constancias educativas firmadas, verificables y sin dependencia de plataformas comerciales.**

LibreConstancia es una herramienta abierta para organizaciones educativas, colectivos comunitarios y proyectos de formación. Permite generar constancias en formato JSON, firmarlas con Ed25519, comprobar que no fueron alteradas y crear códigos QR que abren un verificador web estático. El código funciona sin cuentas, servidores de pago, bases de datos ni servicios de terceros.

**Estado:** versión inicial funcional (MVP 0.1). Todavía no es un sistema integral de matrícula, pagos, PDF o administración educativa.

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

2. **Preparar el verificador web**:

   ```bash
   libreconstancia publish --public-key private-keys/public.json --output public
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

4. **Verificar sin Internet**, usando únicamente la clave pública oficial:

   ```bash
   libreconstancia verify --certificate constancia.json --public-key private-keys/public.json
   ```

5. **Verificar en el navegador:** visita la dirección que imprimió `issue` o escanea `constancia-qr.png`. Si se altera cualquier campo firmado, la comprobación falla.

## Qué contiene el proyecto

| Componente | Uso |
| --- | --- |
| `keygen` | Crea una clave privada cifrada y su clave pública |
| `issue` | Firma datos de una constancia y genera un enlace/QR opcional |
| `verify` | Comprueba el documento contra una clave pública previamente confiable |
| `publish` | Genera un sitio web estático de verificación, sin backend |
| `tests/` | Pruebas para firmas válidas, manipulación, claves diferentes y errores |

## Seguridad y privacidad

- La clave privada nunca se copia al verificador público y siempre se almacena cifrada con contraseña.
- Una constancia firmada debe verificarse con la **clave pública obtenida del emisor por una vía confiable**. Un documento no puede demostrar por sí mismo quién controla una institución.
- El QR incluye la información de la constancia **en texto codificado, no cifrado**. Si alguien obtiene el QR podrá leer el nombre, el curso y demás datos. No coloques datos sensibles ni lo publiques sin autorización.
- El contenido del QR viaja en el fragmento `#c=`; el navegador no envía ese fragmento al servidor HTTP. El verificador no tiene analíticas ni scripts de terceros.
- La versión 0.1 **no permite revocación**. No uses esta versión para certificados cuyo estado necesite invalidarse posteriormente; está planificado para la siguiente versión.
- Un sitio falso podría instalar su propia clave y mostrar una verificación engañosa. Comprueba siempre el dominio del emisor.
- La autenticidad técnica no demuestra asistencia, calidad educativa ni aprobación gubernamental.

Consulta [SECURITY.md](SECURITY.md) para limitaciones y reportes de vulnerabilidades.

## Hoja de ruta abierta

En [ROADMAP.md](ROADMAP.md) están las prioridades: revocación verificable, descarga de PDF, integración con Moodle y WordPress, y pruebas de interoperabilidad. Se aceptan aportes, traducciones y reportes de problemas.

## Participar

Consulta [CONTRIBUTING.md](CONTRIBUTING.md). No necesitamos clientes de pago ni registros para colaborar. Publica problemas reproducibles, ejemplos o mejoras para entidades pequeñas.

## Licencia

MIT. Consulta [LICENSE](LICENSE). Autor inicial: Jhonnier Díaz Perdomo, Colombia.
