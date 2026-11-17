# Prueba sin datos personales ni claves privadas

Estos cuatro archivos contienen **datos completamente ficticios**. La clave privada usada para firmarlos se descartó; aquí solo se publica su clave **pública**.

Instala el proyecto desde la raíz: `python -m pip install -e '.[qr]'`.

### 1. Comparar dos resultados por terminal

```bash
libreconstancia verify \
  --certificate examples/demo/credential-valid.json \
  --public-key examples/demo/public-key.json \
  --revocations examples/demo/revocations.json

libreconstancia verify \
  --certificate examples/demo/credential-revoked.json \
  --public-key examples/demo/public-key.json \
  --revocations examples/demo/revocations.json
```

El primer comando muestra firma válida y ausencia de revocación en la lista firmada del **17 de noviembre de 2026**. El segundo sale con código 2 e indica que la constancia **figura revocada**.

### 2. Probar el verificador web

La manera más sencilla es iniciar el sitio de demostración incluido en `docs/`:

```bash
python -m http.server 8000 --directory docs
```

Visita `http://localhost:8000`, donde dos botones permiten comparar constancias de ejemplo válidas y revocadas. La página no envía información a terceros.

También puedes probar la publicación de tu propio verificador estático. No necesitas una clave privada:

```bash
libreconstancia publish \
  --public-key examples/demo/public-key.json \
  --revocations examples/demo/revocations.json \
  --output demo-public

python -m http.server 8000 --directory demo-public
```

En otra terminal, crea el enlace de cualquiera de los dos documentos firmados:

```bash
libreconstancia link \
  --certificate examples/demo/credential-valid.json \
  --public-key examples/demo/public-key.json \
  --verify-url http://localhost:8000/index.html
```

Abre en el navegador el enlace generado. Puedes cambiar el archivo a `credential-revoked.json` para comprobar el aviso de revocación. El programa también admite `--qr ejemplo.png` para obtener la imagen QR.

### Límites de esta demostración

- Los nombres y la entidad emisora son inventados. Ningún archivo acredita formación real.
- La firma permite verificar que el contenido no cambió, no que el emisor esté acreditado.
- La lista de revocaciones está fechada: **no demuestra el estado actual** de documentos reales.
- No utilices estas claves o nombres ficticios para emitir certificados auténticos.
