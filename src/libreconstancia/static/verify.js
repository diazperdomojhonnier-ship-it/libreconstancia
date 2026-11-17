// Simple verifier with no tracking, CDN or external dependencies.
const status = document.querySelector('#status');
const details = document.querySelector('#details');

function fail(message) {
  status.className = 'error';
  status.textContent = `No verificado: ${message}`;
}

function decode64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error('codificación inválida');
  }
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function utf8(bytes) { return new TextDecoder('utf-8', {fatal: true}).decode(bytes); }

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function validPayload(p) {
  const keys = ['certificate_id', 'hours', 'issued_on', 'issuer', 'participant', 'program', 'schema'];
  if (!p || typeof p !== 'object' || Array.isArray(p) || JSON.stringify(Object.keys(p).sort()) !== JSON.stringify(keys)) return false;
  if (p.schema !== 1 || !Number.isInteger(p.hours) || p.hours < 1 || p.hours > 100000) return false;
  for (const k of ['issuer', 'participant', 'program']) {
    if (typeof p[k] !== 'string' || !p[k].trim() || p[k].length > 250) return false;
  }
  if (typeof p.certificate_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(p.certificate_id)) return false;
  if (typeof p.issued_on !== 'string' || !/^\d{4}-\d\d-\d\d$/.test(p.issued_on)) return false;
  const d = new Date(`${p.issued_on}T00:00:00Z`);
  return !Number.isNaN(d.valueOf()) && d.toISOString().slice(0, 10) === p.issued_on;
}

async function main() {
  try {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const encoded = fragment.get('c');
    if (!encoded) throw new Error('escanea el QR de una constancia firmada para comenzar');
    if (encoded.length > 10000) throw new Error('documento demasiado grande');
    const cert = JSON.parse(utf8(decode64url(encoded)));
    if (!cert || typeof cert !== 'object' || Array.isArray(cert) ||
        JSON.stringify(Object.keys(cert).sort()) !== JSON.stringify(['key_id', 'payload', 'signature'])) {
      throw new Error('estructura de firma incorrecta');
    }
    if (!validPayload(cert.payload)) throw new Error('campos del documento inválidos');
    if (typeof cert.key_id !== 'string' || !/^[0-9a-f]{32}$/.test(cert.key_id)) throw new Error('identificador de clave inválido');
    const response = await fetch('./trusted-keys.json', {cache: 'no-cache'});
    if (!response.ok) throw new Error('no fue posible cargar las claves oficiales');
    const bundle = await response.json();
    const key = Array.isArray(bundle.keys) && bundle.keys.find(k => k.key_id === cert.key_id && k.algorithm === 'Ed25519');
    if (!key) throw new Error('clave emisora desconocida para este sitio');
    const publicBytes = decode64url(key.public_key);
    const signatureBytes = decode64url(cert.signature);
    if (publicBytes.length !== 32 || signatureBytes.length !== 64) throw new Error('tamaño de clave o firma inválido');
    const fingerprint = await crypto.subtle.digest('SHA-256', publicBytes);
    const derivedId = Array.from(new Uint8Array(fingerprint)).map(byte => byte.toString(16).padStart(2, '0')).join('').slice(0, 32);
    if (derivedId !== cert.key_id) throw new Error('la identificación de la clave no coincide');
    const trustedKey = await crypto.subtle.importKey('raw', publicBytes, {name: 'Ed25519'}, false, ['verify']);
    const valid = await crypto.subtle.verify('Ed25519', trustedKey, signatureBytes, new TextEncoder().encode(canonical(cert.payload)));
    if (!valid) throw new Error('la firma no coincide con el contenido');
    for (const field of ['participant', 'program', 'issuer', 'issued_on', 'certificate_id']) {
      document.getElementById(field).textContent = cert.payload[field];
    }
    document.getElementById('hours').textContent = `${cert.payload.hours} horas`;
    details.hidden = false;
    status.className = 'ok';
    status.textContent = 'Firma válida · Documento íntegro y firmado por la clave reconocida en este sitio';
  } catch (error) {
    fail(error.message || 'No se pudo verificar');
  }
}

main();
