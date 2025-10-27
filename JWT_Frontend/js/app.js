// static/js/app.js - versión simplificada: usa siempre PyJWT en el backend

const output = document.getElementById("output");
const outputTitle = document.getElementById("outputTitle");
const jwtInput = document.getElementById("jwtInput");
const analyzeAllBtn = document.getElementById("analyzeAllBtn");
const lexicoBtn = document.getElementById("lexicoBtn");
const sintacticoBtn = document.getElementById("sintacticoBtn");
const semanticoBtn = document.getElementById("semanticoBtn");
const encodeBtn = document.getElementById("encodeBtn");
const payloadInput = document.getElementById("payloadInput");
const secretInput = document.getElementById("secretInput");
const algorithmSelect = document.getElementById("algorithmSelect");
const expirationInput = document.getElementById("expirationInput");
const validateBtn = document.getElementById("validateBtn");

const API_URL = "http://127.0.0.1:5000/api/analyze";
const API_ENCODE_URL = "http://127.0.0.1:5000/api/encode";
const API_VALIDATE_SECRET_URL = "http://127.0.0.1:5000/api/validate-secret";
const API_DECODE_VERIFY_URL = "http://127.0.0.1:5000/api/decode-verify";

function createSection(title, content) {
  return `
    <div class="section">
      <h3>${title}</h3>
      <pre>${typeof content === "string" ? content : JSON.stringify(content, null, 2)}</pre>
    </div>
  `;
}

function showOutput(title, htmlContent) {
  outputTitle.textContent = title;
  output.innerHTML = htmlContent;
}

function showLoading(message = "Procesando...") {
  output.innerHTML = `<p class="loading">⏳ ${message}</p>`;
}

function showError(message) {
  output.innerHTML = `<p style='color:red;'>❌ ${message}</p>`;
}

// (mantén aquí tus listeners de análisis léxico/sintáctico/semántico — los dejo iguales a tu versión original)
// Para no repetir el código extenso en este bloque, asumo que ya tienes esas partes copiadas tal cual.
// A continuación la parte de codificación que siempre envía use_pyjwt: true

encodeBtn.addEventListener("click", async () => {
  const payloadText = payloadInput.value.trim();
  const secret = secretInput.value.trim();
  const algorithm = algorithmSelect.value;
  const expiresIn = expirationInput.value ? parseInt(expirationInput.value) : null;

  if (!payloadText) return alert("❌ Por favor ingresa el payload en formato JSON.");
  if (!secret) return alert("❌ Por favor ingresa la clave secreta.");

  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch {
    return alert("❌ El payload no tiene formato JSON válido. Verifica la sintaxis.");
  }

  showOutput("Codificando JWT...", "");
  showLoading("Generando token JWT...");

  try {
    const body = {
      payload,
      secret,
      algorithm,
      expires_in: expiresIn,
      validate_secret: true,
      use_pyjwt: true   // <-- siempre PyJWT
    };

    const res = await fetch(API_ENCODE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      let errorHtml = `
        <div class="section" style="background-color: #ffebee; border-left: 4px solid #f44336;">
          <h3>❌ Error en codificación</h3>
          <p>${data.error || "Error en la petición"}</p>
        </div>
      `;
      if (data.warnings?.length) {
        errorHtml += `
          <div class="section" style="background-color: #fff3e0; border-left: 4px solid #ff9800;">
            <h3>⚠️ Advertencias</h3>
            <ul>
              ${data.warnings.map(w => `<li>${w}</li>`).join('')}
            </ul>
          </div>
        `;
      }
      showOutput("❌ Error en codificación", errorHtml);
      return;
    }

    let html = `
      <div class="section" style="background-color: #e8f5e9; border-left: 4px solid #4caf50;">
        <h3>✅ Token JWT Generado (${data.method})</h3>
        <textarea id="generatedTokenArea" readonly style="width:100%; min-height:100px; font-family:monospace; padding:10px; border:1px solid #ddd; border-radius:4px;">${data.jwt}</textarea>
        <div style="margin-top:10px;">
          <button id="copyTokenBtn">📋 Copiar Token</button>
        </div>
      </div>
      <div class="section"><h3>🧩 Header</h3><pre>${JSON.stringify(data.header, null, 2)}</pre></div>
      <div class="section"><h3>💾 Payload</h3><pre>${JSON.stringify(data.payload, null, 2)}</pre></div>
      <div class="section"><h3>🔏 Firma (Signature)</h3><pre style="word-break: break-all;">${data.signature}</pre></div>
    `;

    if (data.warnings?.length) {
      html = `
        <div class="section" style="background-color: #fff3e0; border-left: 4px solid #ff9800;">
          <h3>⚠️ Advertencias</h3><ul>${data.warnings.map(w=>`<li>${w}</li>`).join('')}</ul>
        </div>` + html;
    }

    showOutput("🔐 JWT Codificado Exitosamente", html);

    jwtInput.value = data.jwt;

    const copyBtn = document.getElementById("copyTokenBtn");
    const tokenArea = document.getElementById("generatedTokenArea");
    if (copyBtn && tokenArea) {
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(tokenArea.value);
          copyBtn.textContent = "✔️ Copiado";
          setTimeout(()=> copyBtn.textContent = "📋 Copiar Token", 1500);
        } catch {
          alert("No se pudo copiar automáticamente. Selecciona el token y copia manualmente.");
        }
      });
    }

  } catch (err) {
    showError(`Error al codificar: ${err.message || err}`);
  }
});
// decodeVerifyFromUI: realiza POST a /api/decode-verify y muestra resultado
// -------------------- decodeVerifyFromUI (usar verifySecretInput si existe) --------------------
// decodeVerifyFromUI - usa verifySecretInput si existe
async function decodeVerifyFromUI() {
  const token = (document.getElementById('jwtInput') || {}).value?.trim();
  const secretForVerify = (document.getElementById('verifySecretInput') || {}).value?.trim();

  if (!token) {
    alert("Por favor ingresa el token JWT en el área superior.");
    return;
  }

  showOutput("Verificando token...", "");
  showLoading("Enviando petición de verificación...");

  try {
    const body = { jwt: token, verify: true };
    if (secretForVerify) body.secret = secretForVerify;

    const res = await fetch(API_DECODE_VERIFY_URL, {
      method: "POST",
      mode: "cors",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    console.log("fetch status:", res.status, "url:", API_DECODE_VERIFY_URL);

    const data = await res.json().catch(() => null);
    if (!data) {
      showError("Respuesta inválida del servidor (no JSON). Revisa Network y la consola del servidor.");
      return;
    }

    if (data.success && data.verified === false) {
      const html = `
        <div class="section" style="background:#fff7cc; border-left:4px solid #f59e0b;">
          <h3>⚠️ Decodificado sin verificación</h3>
          <p>No se proporcionó clave para verificar la firma. Los datos mostrados no están validados.</p>
        </div>
        <div class="section"><h3>Header</h3><pre>${JSON.stringify(data.header ?? {}, null, 2)}</pre></div>
        <div class="section"><h3>Payload</h3><pre>${JSON.stringify(data.payload ?? {}, null, 2)}</pre></div>
      `;
      showOutput("Resultado (sin verificación)", html);
      return;
    }

    if (data.success && data.verified === true) {
      showOutput("✅ Token válido", `<div class="section"><h3>Payload</h3><pre>${JSON.stringify(data.payload, null, 2)}</pre></div>`);
      return;
    }

    // errores
    showOutput("❌ Verificación fallida", `<pre>${JSON.stringify(data, null, 2)}</pre>`);
  } catch (err) {
    console.error("Error en decodeVerifyFromUI:", err);
    showError(`Error de red/servidor: ${err.message || err}`);
  }
}

// Adjuntar listener al botón validateBtn (id debe existir)
(function attachValidateButton() {
  const attach = () => {
    const btn = document.getElementById("validateBtn");
    if (!btn) {
      console.warn("validateBtn no encontrado.");
      return;
    }
    btn.type = "button";
    btn.removeEventListener("click", decodeVerifyFromUI);
    btn.addEventListener("click", (e) => { e.preventDefault(); decodeVerifyFromUI(); });
    console.log("Listener validateBtn adjuntado (usa verifySecretInput si existe).");
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attach);
  } else {
    attach();
  }
})();
