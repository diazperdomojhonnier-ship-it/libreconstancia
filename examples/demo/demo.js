// Demo with synthetic records only; no tracking or external API calls.
async function openSample(filename) {
  const message = document.getElementById('message');
  message.textContent = 'Preparando la verificación…';
  try {
    const response = await fetch(`./${filename}`, {cache: 'no-store'});
    if (!response.ok) throw new Error('No se pudo cargar el ejemplo');
    const record = await response.json();
    const bytes = new TextEncoder().encode(JSON.stringify(record));
    const raw = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    const encoded = btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    window.location.href = `./verify/index.html#c=${encoded}`;
  } catch (error) {
    message.textContent = `Error: ${error.message || 'No disponible'}`;
  }
}

for (const button of document.querySelectorAll('[data-document]')) {
  button.addEventListener('click', () => openSample(button.dataset.document));
}
