from flask import Blueprint, request, jsonify
from app.services.lexer_service import JWTLexer
from app.models.db import db, test_cases
from app.services.lexer_service import Alfabeto
from app.services.sintactico import JWTParser
from app.services.semantic_service import analizar_header_semantico, analizar_payload_semantico, validar_tiempo, generar_tabla_simbolos


jwt_bp = Blueprint("jwt_bp", __name__)

#from app.models.db import guardar_resultado

@jwt_bp.route("/analyze", methods=["POST"])
def analyze_jwt():
    data = request.get_json()
    token = data.get("jwt")
    nombre = data.get("nombre", "Caso sin nombre")

    lexer = JWTLexer(token)
    lexer.tokenizar()
    lexer.decodificar_componentes()
    lexer.analizar_estructura_json()

    alfabeto_info = Alfabeto.describir_alfabeto()

    resultado = {
        "alfabeto": alfabeto_info,
        "tokens": [t.to_dict() for t in lexer.tokens],
        "header_decodificado": lexer.header_decodificado,
        "payload_decodificado": lexer.payload_decodificado,
        "errores": lexer.errores,
        "advertencias": lexer.advertencias
    }

    # === FASE 2: SINTÁCTICO ===
    parser = JWTParser(lexer.tokens)
    sintaxis_valida = parser.parsear()
    resultado["sintactico"] = {
        "valido": sintaxis_valida,
        "errores": parser.errores,
        "arbol_sintactico": parser.generar_arbol()
    }

   # guardar_resultado(nombre, token, resultado)

   # === FASE 3: SEMANTICA ===
    # === FASE 3: SEMÁNTICA ===
    errores_header = analizar_header_semantico(lexer.header_decodificado)
    errores_payload = analizar_payload_semantico(lexer.payload_decodificado)
    validacion_tiempo = validar_tiempo(lexer.payload_decodificado)
    tabla_simbolos = generar_tabla_simbolos(
        lexer.header_decodificado, lexer.payload_decodificado
    )

    resultado["semantico"] = {
        "errores": errores_header + errores_payload,
        "validacion_tiempo": validacion_tiempo,
        "tabla_simbolos": tabla_simbolos
    }
    return jsonify(resultado)


@jwt_bp.route("/test-db", methods=["GET"])
def test_db():
    try:
        # Inserta un documento de prueba
        test_cases.insert_one({"test": "conexion_exitosa"})
        count = test_cases.count_documents({})
        return jsonify({
            "mensaje": "Conexión a MongoDB exitosa ✅",
            "documentos_totales": count
        })
    except Exception as e:
        return jsonify({
            "error": f"No se pudo conectar a MongoDB ❌: {str(e)}"
        }), 500