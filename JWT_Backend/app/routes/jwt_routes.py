from flask import Blueprint, request, jsonify
from app.services.lexer_service import JWTLexer
from app.models.db import db, test_cases
from app.services.lexer_service import Alfabeto
from app.services.sintactico import JWTParser
from app.services.semantic_service import analizar_header_semantico, analizar_payload_semantico, validar_tiempo, generar_tabla_simbolos
from app.services.encoder_service import JWTEncoder

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


# ===================================================================
# ✅ FASE 5: Codificación de JWT
# ===================================================================
@jwt_bp.route("/encode", methods=["POST"])
def encode_jwt():
    """
    Genera (codifica) un JWT desde un header/payload/secret/algoritmo.
    Ejemplo de body JSON:
    {
      "payload": {"sub": "123", "name": "Alice"},
      "secret": "mi_clave",
      "algorithm": "HS256",
      "header": {"typ": "JWT"},
      "expires_in": 3600
    }
    """
    data = request.get_json() or {}

    payload = data.get("payload")
    secret = data.get("secret")
    algorithm = data.get("algorithm", "HS256")
    header = data.get("header")
    expires_in = data.get("expires_in")
    add_iat = data.get("add_iat", True)

    if not payload or not secret:
        return jsonify({"error": "Se requieren 'payload' y 'secret'"}), 400

    encoder = JWTEncoder()

    # Generar JWT con o sin expiración
    if expires_in:
        result = encoder.encode_with_expiration(
            payload, secret, expires_in_seconds=expires_in, algorithm=algorithm
        )
    else:
        result = encoder.encode(
            payload, secret, algorithm=algorithm, header=header, add_iat=add_iat
        )

    # Registrar en base si deseas
    # test_cases.insert_one({"fase": "codificacion", "resultado": result.__dict__})

    if result.success:
        print(f"✅ JWT generado con éxito ({algorithm})")
    else:
        print(f"❌ Error en generación JWT: {result.error}")

    return jsonify({
        "success": result.success,
        "jwt": result.jwt,
        "header": result.header,
        "payload": result.payload,
        "signature": result.signature,
        "algorithm": result.algorithm,
        "error": result.error
    })

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