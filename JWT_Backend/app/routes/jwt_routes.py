from flask import Blueprint, request, jsonify
from app.services.lexer_service import JWTLexer
from app.models.db import db, test_cases
from app.services.lexer_service import Alfabeto

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

   # guardar_resultado(nombre, token, resultado)

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