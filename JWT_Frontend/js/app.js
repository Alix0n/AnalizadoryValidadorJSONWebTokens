const output = document.getElementById("output");
const outputTitle = document.getElementById("outputTitle");
const jwtInput = document.getElementById("jwtInput");
const analyzeAllBtn = document.getElementById("analyzeAllBtn");
const lexicoBtn = document.getElementById("lexicoBtn");
const sintacticoBtn = document.getElementById("sintacticoBtn");


const API_URL = "http://127.0.0.1:5000/api/analyze";

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
    html += createSection("📘 Árbol Sintáctico", sintactico.arbol_sintactico, "🌳");
    html += createSection("📗 Resultado", sintactico.valido ? "Estructura válida ✅" : "Estructura inválida ❌");
    if (sintactico.errores?.length) {
      html += createSection("❌ Errores Sintácticos", sintactico.errores);
    }

    showOutput("📘 Resultados del Análisis Sintáctico", html);
  } catch (err) {
    showOutput("Error en análisis sintáctico", `<p style='color:red;'>${err.message}</p>`);
  }
});


