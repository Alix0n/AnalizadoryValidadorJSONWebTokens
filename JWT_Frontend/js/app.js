const output = document.getElementById("output");
const outputTitle = document.getElementById("outputTitle");
const jwtInput = document.getElementById("jwtInput");
const analyzeAllBtn = document.getElementById("analyzeAllBtn");
const lexicoBtn = document.getElementById("lexicoBtn");
const sintacticoBtn = document.getElementById("sintacticoBtn");
const encodeBtn = document.getElementById("encodeBtn");
const payloadInput = document.getElementById("payloadInput");
const secretInput = document.getElementById("secretInput");
const algorithmSelect = document.getElementById("algorithmSelect");
const expirationInput = document.getElementById("expirationInput");


const API_URL = "http://127.0.0.1:5000/api/analyze";
const API_ENCODE_URL = "http://127.0.0.1:5000/api/encode";

function createSection(title, content) {
  return `
    <div class="section">
      <h3> ${title}</h3>
      <pre>${typeof content === "string" ? content : JSON.stringify(content, null, 2)}</pre>
    </div>
  `;
}

function showOutput(title, htmlContent) {
  outputTitle.textContent = title;
  output.innerHTML = htmlContent;
}

analyzeAllBtn.addEventListener("click", async () => {
  const jwt = jwtInput.value.trim();
  if (!jwt) return alert("Por favor ingresa un token JWT.");

  showOutput("Analizando token completo...", "<p>Procesando...</p>");

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jwt })
    });

    const data = await res.json();

    let html = "";
    html += createSection("Alfabeto y Delimitadores", data.alfabeto);
    html += createSection("Tokens Identificados", data.tokens);
    html += createSection("Header Decodificado", data.header_decodificado);
    html += createSection("Payload Decodificado", data.payload_decodificado);
    if (data.advertencias?.length) html += createSection("Advertencias", data.advertencias);
    if (data.errores?.length) html += createSection("Errores", data.errores);
    // Fase Sintáctica
    html += createSection("Análisis Sintáctico", data.sintactico);
    // Fase Semántica
    html += createSection("Errores Semánticos", data.semantico.errores);
    html += createSection("Validación Temporal", data.semantico.validacion_tiempo);
    html += createSection("Tabla de Símbolos", data.semantico.tabla_simbolos);
    showOutput("Análisis Completo del Token", html);
  } catch (err) {
    showOutput("Error", `<p style='color:red;'>${err.message}</p>`);
  }
});

lexicoBtn.addEventListener("click", async () => {
  const jwt = jwtInput.value.trim();
  if (!jwt) return alert("Por favor ingresa un token JWT.");

  showOutput("Analizando Fase 1: Léxica...", "<p>Procesando...</p>");

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jwt })
    });

    const data = await res.json();

    let html = "";
    html += createSection("Alfabeto y Delimitadores", data.alfabeto);
    html += createSection("Tokens Identificados", data.tokens);
    html += createSection("Header Decodificado", data.header_decodificado);
    html += createSection("Payload Decodificado", data.payload_decodificado);
    if (data.advertencias?.length) html += createSection("Advertencias", data.advertencias);
    if (data.errores?.length) html += createSection("Errores", data.errores);

    showOutput("Resultados del Análisis Léxico", html);
  } catch (err) {
    showOutput("Error en análisis léxico", `<p style='color:red;'>${err.message}</p>`);
  }
});

const validateBtn = document.getElementById("validateBtn");

validateBtn.addEventListener("click", () => {
  const jwt = jwtInput.value.trim();
  if (!jwt) return alert("Por favor ingresa un token JWT.");

  const partes = jwt.split(".");
  let html = "";

  if (partes.length !== 3) {
    html += "<p style='color:red;'>El token JWT no tiene 3 partes (HEADER.PAYLOAD.SIGNATURE)</p>";
  } else {
    html += "<p style='color:green;'>El token tiene una estructura base válida (3 segmentos)</p>";
    html += "<p><b>HEADER:</b> " + partes[0].substring(0, 20) + "...</p>";
    html += "<p><b>PAYLOAD:</b> " + partes[1].substring(0, 20) + "...</p>";
    html += "<p><b>SIGNATURE:</b> " + partes[2].substring(0, 10) + "...</p>";
  }

  showOutput("Validación de Token JWT", html);
});

// 🔹 Ejecutar solo el análisis sintáctico
sintacticoBtn.addEventListener("click", async () => {
  const jwt = jwtInput.value.trim();
  if (!jwt) return alert("Por favor ingresa un token JWT.");

  showOutput("Analizando Fase 2: Sintáctica...", "<p>Procesando...</p>");

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jwt })
    });

    const data = await res.json();
    const sintactico = data.sintactico;

    // Formatear visualmente la información sintáctica
    let html = "";
    html += createSection("Árbol Sintáctico", sintactico.arbol_sintactico);
    html += createSection("Resultado", sintactico.valido ? "Estructura válida " : "Estructura inválida ");
    if (sintactico.errores?.length) {
      html += createSection("Errores Sintácticos", sintactico.errores);
    }

    showOutput("Resultados del Análisis Sintáctico", html);
  } catch (err) {
    showOutput("Error en análisis sintáctico", `<p style='color:red;'>${err.message}</p>`);
  }
});

semanticoBtn.addEventListener("click", async () => {
  const jwt = jwtInput.value.trim();
  if (!jwt) return alert("Por favor ingresa un token JWT.");

  showOutput("Analizando Fase 3: Semántica...", "<p>Procesando...</p>");

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jwt })
    });

    const data = await res.json();
    const semantico = data.semantico;

    let html = "";

    html += createSection("Errores Semánticos", semantico.errores.length ? semantico.errores : "Sin errores");

    html += createSection("Validación Temporal", semantico.validacion_tiempo);

    const tablaHTML = `
      <table class="symbol-table">
        <thead>
          <tr>
            <th>Componente</th>
            <th>Nombre</th>
            <th>Tipo</th>
            <th>Valor</th>
          </tr>
        </thead>
        <tbody>
          ${semantico.tabla_simbolos.map(row => `
            <tr>
              <td>${row.componente}</td>
              <td>${row.nombre}</td>
              <td>${row.tipo}</td>
              <td>${row.valor}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;

    html += createSection("Tabla de Símbolos", tablaHTML);

    showOutput("Resultados del Análisis Semántico", html);
  } catch (err) {
    showOutput("Error en análisis semántico", `<p style='color:red;'>${err.message}</p>`);
  }
});

encodeBtn.addEventListener("click", async () => {
  const payloadText = payloadInput.value.trim();
  const secret = secretInput.value.trim();
  const algorithm = algorithmSelect.value;
  const expiresIn = expirationInput.value ? parseInt(expirationInput.value) : null;

  if (!payloadText || !secret)
    return alert("Por favor ingresa el payload (JSON válido) y la clave secreta.");

  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch {
    return alert("❌ El payload no tiene formato JSON válido.");
  }

  showOutput("Codificando JWT...", "<p>Procesando...</p>");

  try {
    const res = await fetch(API_ENCODE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload, secret, algorithm, expires_in: expiresIn })
    });

    const data = await res.json();

    if (!data.success) {
      showOutput("❌ Error en codificación", `<p>${data.error}</p>`);
      return;
    }

    let html = `
      <div class="section">
        <h3>✅ Token Generado</h3>
        <pre>${data.jwt}</pre>
      </div>
      <div class="section">
        <h3>🧩 Header</h3>
        <pre>${JSON.stringify(data.header, null, 2)}</pre>
      </div>
      <div class="section">
        <h3>💾 Payload</h3>
        <pre>${JSON.stringify(data.payload, null, 2)}</pre>
      </div>
      <div class="section">
        <h3>🔏 Firma</h3>
        <pre>${data.signature}</pre>
      </div>
    `;

    showOutput("🔐 Resultado de Codificación JWT", html);
  } catch (err) {
    showOutput("Error", `<p style="color:red;">${err.message}</p>`);
  }
});