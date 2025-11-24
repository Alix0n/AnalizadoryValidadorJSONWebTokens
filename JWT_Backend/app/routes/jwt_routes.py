from flask import Blueprint, request, jsonify
from app.services.encoder_service import JWTEncoder, SecretKeyManager
from app.services.lexer_service import JWTLexer, Alfabeto
from app.services.sintactico import JWTParser
from app.services.semantic_service import analizar_header_semantico, analizar_payload_semantico, validar_tiempo, generar_tabla_simbolos
from app.models.db import db, test_cases
from app.models.db import guardar_resultado
import jwt  # PyJWT

jwt_bp = Blueprint("jwt_bp", __name__, url_prefix="/api")

@jwt_bp.route("/analyze", methods=["POST"])
def analyze_jwt():
    data = request.get_json() or {}
    token = data.get("jwt", "")
    

    if not token:
        return jsonify({"success": False, "error": "No se recibió un token JWT."}), 400

    partes = token.split(".")


    if len(partes) != 3:
        
        return jsonify({
            "success": False,
            "error": "El token JWT está incompleto. Debe tener formato header.payload.signature"
        }), 400

    header, payload, signature = partes

    if not header or not payload or not signature:
        return jsonify({
            "success": False,
            "error": "El token JWT está incompleto. Debe tener formato header.payload.signature"
        }), 400

    
    lexer = JWTLexer(token)
    lexer.tokenizar()
    lexer.decodificar_componentes()
    lexer.analizar_estructura_json()
    alfabeto_info = Alfabeto.describir_alfabeto()
    reporte = lexer.generar_reporte() 
    estructura_detectada = {
    "entrada": lexer.entrada,
    "longitud": len(lexer.entrada),
    "header": len(lexer.tokens[0].valor) if lexer.tokens else 0,
    "payload": len(lexer.tokens[2].valor) if lexer.tokens else 0,
    "signature": len(lexer.tokens[4].valor) if lexer.tokens else 0
}

    resultado = {
        "alfabeto": alfabeto_info,
        "tokens": [t.to_dict() for t in lexer.tokens],
        "header_decodificado": lexer.header_decodificado,
        "payload_decodificado": lexer.payload_decodificado,
        "errores": lexer.errores,
        "advertencias": lexer.advertencias,
        "reporte_analisis_lexico": reporte ,
        "estructura_detectada": estructura_detectada,
        "es_malformado": lexer.es_malformado()
        
    }

    # Sintáctico
    parser = JWTParser(lexer.tokens)
    sintaxis_valida = parser.parsear()
    resultado["sintactico"] = {
        "valido": sintaxis_valida,
        "errores": parser.errores,
        "gramatica": parser.mostrar_producciones(),
        "derivaciones": parser.mostrar_derivaciones(),
        "arbol_sintactico": parser.generar_arbol()
    }

    # Semántico
    errores_header = analizar_header_semantico(lexer.header_decodificado)
    errores_payload = analizar_payload_semantico(lexer.payload_decodificado)
    
    # Validar tiempo
    validacion_tiempo = validar_tiempo(lexer.payload_decodificado)

    # Determinar vigencia real
    vigente = validacion_tiempo["estado"] == "valido"

    if lexer.payload_decodificado is None:
        resultado["semantico"] = {
            "errores": errores_header + ["El payload no es JSON válido o no pudo decodificarse."],
            "validacion_tiempo": {
                "estado": validacion_tiempo["estado"],
                "fecha_actual": validacion_tiempo["fecha_actual"],
                "fecha_emision": validacion_tiempo["fecha_emision"],
                "fecha_expiracion": validacion_tiempo["fecha_exp"],
                "detalles": validacion_tiempo["detalle"],
                "vigente": vigente
            },
            "tabla_simbolos": []
        }
        resultado["descripcion"] = clasificar_token(token, resultado)
        guardar_resultado(resultado["descripcion"], token, resultado)  # <-- se guarda siempre
        return jsonify(resultado)
    # ----------------------------------------------------------

    validacion_tiempo = validar_tiempo(lexer.payload_decodificado)
    tabla_simbolos = generar_tabla_simbolos(lexer.header_decodificado, lexer.payload_decodificado)


    resultado["semantico"] = {
    "errores": errores_header + errores_payload,
    "validacion_tiempo": {
        "estado": validacion_tiempo["estado"],
        "fecha_actual": validacion_tiempo["fecha_actual"],
        "fecha_emision": validacion_tiempo["fecha_emision"],
        "fecha_expiracion": validacion_tiempo["fecha_exp"],   
        "detalles": validacion_tiempo["detalle"],             
        "vigente": validacion_tiempo["estado"] == "valido"   # <-- usar directamente

    },
    "tabla_simbolos": tabla_simbolos
}

    resultado["descripcion"] = clasificar_token(token, resultado)
    guardar_resultado(resultado["descripcion"], token, resultado)

    return jsonify(resultado)

def clasificar_token(token, resultado):
    """
    Clasifica el token según errores detectados o estado.
    Devuelve un string con la descripción.
    """
    # 1. Revisar token malformado
    if resultado.get("es_malformado"):  # <- flag del lexer
        return "Token malformado (sintaxis incorrecta)"

    semantico = resultado.get("semantico", {})
    validacion_tiempo = semantico.get("validacion_tiempo", {})
    errores_payload = semantico.get("errores", [])

    estado = validacion_tiempo.get("estado", "")
    detalles = validacion_tiempo.get("detalles", [])

    # 2. Firma inválida
    if "Firma inválida" in errores_payload:
        return "Token con firma inválida"

    # 3. Si el token no es "válido", manejar expirado o futuro
    if estado != "valido":
        if estado == "expirado" or any("expirado" in d.lower() for d in detalles):
            return "Token expirado"
        if estado == "no_activo" or any("aún no está activo" in d.lower() for d in detalles):
            return "Token emitido en el futuro"
        if estado == "error":
            return "Token con claims de tiempo inválidos"

    # 4. Token es válido, pero revisar si en los detalles dice expirado
    if estado == "valido" and any("expirado" in d.lower() for d in detalles):
        return "Token expirado"

    # 5. Claims faltantes
    if any("Campo obligatorio" in e for e in errores_payload):
        return "Token con claims faltantes"

    # 6. Tipos de datos incorrectos
    if any("tipo de dato" in e.lower() for e in errores_payload):
        return "Token con tipos de datos incorrectos"

    # 7. Todo correcto → válido
    return "Token válido"


@jwt_bp.route("/encode", methods=["POST"])
def encode_jwt():
    try:
        data = request.get_json() or {}
        payload = data.get("payload")
        secret = data.get("secret")
        if not payload:
            return jsonify({"success": False, "error": "El campo 'payload' es requerido"}), 400
        if not secret:
            return jsonify({"success": False, "error": "El campo 'secret' es requerido"}), 400

        algorithm = data.get("algorithm", "HS256")
        header = data.get("header")
        expires_in = data.get("expires_in")
        add_iat = data.get("add_iat", True)
        validate_secret = data.get("validate_secret", True)

        # Usa tu JWTEncoder (que internamente puede usar PyJWT)
        encoder = JWTEncoder(validate_secret=validate_secret)

        if expires_in:
            result = encoder.encode_with_expiration(payload=payload, secret=secret, expires_in_seconds=expires_in, algorithm=algorithm)
        else:
            result = encoder.encode(payload=payload, secret=secret, algorithm=algorithm, header=header, add_iat=add_iat)

        if result.success:
            response = {
                "success": True,
                "jwt": result.jwt,
                "header": result.header,
                "payload": result.payload,
                "signature": result.signature,
                "algorithm": result.algorithm,
                "method": result.method
            }
            if result.warnings:
                response["warnings"] = result.warnings
            return jsonify(response), 200
        else:
            return jsonify({"success": False, "error": result.error}), 400

    except Exception as e:
        return jsonify({"success": False, "error": f"Error interno: {str(e)}"}), 500


@jwt_bp.route("/decode-verify", methods=["POST"])
def decode_verify_jwt():
    """
    Decodifica y verifica un JWT usando PyJWT.
    - Si 'secret' no se proporciona -> decodifica sin verificar (verified: False).
    - Si 'secret' se proporciona -> intenta verificar la firma (verified True/False).
    Respuesta siempre incluye "success" y "verified" (boolean).
    """
    try:
        data = request.get_json() or {}
        token = data.get("jwt")
        secret = data.get("secret", None)  # ahora opcional
        algorithms = data.get("algorithms")  # opcional
        verify = data.get("verify", True)

        if not token:
            return jsonify({"success": False, "verified": False, "error": "El campo 'jwt' es requerido"}), 400

        # Inferir algoritmo si no se pasó
        if not algorithms:
            try:
                header = jwt.get_unverified_header(token)
                alg = header.get("alg")
                algorithms = [alg] if alg else ['HS256', 'HS384', 'HS512']
            except Exception:
                algorithms = ['HS256', 'HS384', 'HS512']

        # Si no hay secret: decodificar sin verificar y devolver header+payload
        if not secret:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                header = jwt.get_unverified_header(token)
                return jsonify({
                    "success": True,
                    "verified": False,
                    "warning": "No se proporcionó clave para verificar la firma. Se decodificó sin verificación.",
                    "header": header,
                    "payload": payload
                }), 200
            except Exception as e:
                return jsonify({"success": False, "verified": False, "error": f"No se pudo decodificar el token: {str(e)}"}), 400

        # Si se proporciona secret -> intento de verificación real
        try:
            # PyJWT acepta secret string (HS*) o public key PEM (RS*)
            decoded = jwt.decode(token, secret, algorithms=algorithms, options={"verify_signature": verify})
            return jsonify({"success": True, "verified": True, "payload": decoded}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "verified": False, "error": "El token ha expirado"}), 400
        except jwt.InvalidSignatureError:
            return jsonify({"success": False, "verified": False, "error": "Firma inválida"}), 400
        except jwt.InvalidTokenError as e:
            return jsonify({"success": False, "verified": False, "error": f"Token inválido: {str(e)}"}), 400

    except Exception as e:
        return jsonify({"success": False, "verified": False, "error": f"Error al decodificar: {str(e)}"}), 500

@jwt_bp.route("/history", methods=["GET"])
def history():
    try:
        resultados = list(test_cases.find({}, {"_id": 0, "token": 1, "descripcion": 1}))
        return jsonify({"success": True, "data": resultados})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@jwt_bp.route("/validate-secret", methods=["POST"])
def validate_secret():
    try:
        data = request.get_json() or {}
        secret = data.get('secret', '')
        min_length = data.get('min_length', 32)
        if not secret:
            return jsonify({"valid": False, "message": "La clave secreta no puede estar vacía", "length": 0, "min_length": min_length}), 400
        is_valid, error_msg = SecretKeyManager.validate_secret_key(secret, min_length)
        response = {
            "valid": is_valid,
            "message": error_msg if not is_valid else "✅ La clave secreta es suficientemente segura",
            "length": len(secret),
            "min_length": min_length,
            "recommendations": []
        }
        if not is_valid:
            if len(secret) < min_length:
                response["recommendations"].append(f"Aumenta la longitud a al menos {min_length} caracteres")
            if not any(c.isupper() for c in secret):
                response["recommendations"].append("Agrega al menos una letra mayúscula")
            if not any(c.islower() for c in secret):
                response["recommendations"].append("Agrega al menos una letra minúscula")
            if not any(c.isdigit() for c in secret):
                response["recommendations"].append("Agrega al menos un número")
            if not any(not c.isalnum() for c in secret):
                response["recommendations"].append("Agrega al menos un carácter especial (!@#$%^&*)")
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"valid": False, "error": f"Error al validar: {str(e)}"}), 500

@jwt_bp.route("/verify-signature", methods=["POST"])
def verify_signature():
    data = request.get_json()
    token = data.get("jwt")
    secret = data.get("secret")

    encoder = JWTEncoder()
    result = encoder.decode_and_verify(token, secret)

    return jsonify(result)







