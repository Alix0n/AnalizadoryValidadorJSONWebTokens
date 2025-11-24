from datetime import datetime, timezone

def analizar_header_semantico(header):
    errores = []
    campos_obligatorios = ["alg", "typ"]

    if not isinstance(header, dict):
        return ["El header no tiene formato JSON válido"]

    for campo in campos_obligatorios:
        if campo not in header:
            errores.append(f"Campo obligatorio '{campo}' no encontrado en header")

    return errores


def convertir_fecha(timestamp):
    """Convierte un timestamp UNIX a fecha legible"""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "⚠️ Valor no convertible a fecha"


def convertir_entero(valor, nombre, errores):
    if valor is None:
        return None
    try:
        return int(valor)
    except:
        errores.append(f"El claim '{nombre}' debe ser un número entero (recibido: {type(valor).__name__})")
        return None


def analizar_payload_semantico(payload):
    errores = []

    if not isinstance(payload, dict):
        return ["El payload no tiene formato JSON válido"]

    obligatorio = ["sub"]
    opcionales = ["iat", "exp"]   # Se validan solo si existen
    ignorar = ["iss", "aud", "nbf"]  # Ya NO se consideran obligatorios

    # Claims personalizados no generan error

    # ----- Validación de claims obligatorios -----
    for claim in obligatorio:
        if claim not in payload:
            errores.append(f"Claim obligatorio '{claim}' no encontrado en el payload")

    # ----- Validación opcionales -----
    for claim in opcionales:
        if claim in payload:
            valor = payload[claim]
            if isinstance(valor, str):
                if valor.isdigit():
                    payload[claim] = int(valor)
                else:
                    errores.append(f"Claim '{claim}' debe ser un entero, no '{valor}'")
            elif not isinstance(valor, int):
                errores.append(f"Claim '{claim}' debe ser un entero")

    # ----- Claims ignorados -----
    # iss, aud, nbf → no se validan ni se reporta error

    return errores


def validar_tiempo(payload):

    if payload is None:
        return {
            "estado": "error",
            "detalle": ["El payload no es válido, no se puede validar el tiempo."],
            "fecha_actual": None,
            "fecha_exp": None,
            "fecha_inicio": None,
            "fecha_emision": None
        }

    ahora = int(datetime.now(timezone.utc).timestamp())

    exp = payload.get("exp")
    nbf = payload.get("nbf")  # Ignorado si no existe
    iat = payload.get("iat")

    respuesta = {
        "estado": None,
        "detalle": [],
        "fecha_actual": convertir_fecha(ahora),
        "fecha_exp": None,
        "fecha_inicio": None,
        "fecha_emision": None
    }

    # Si no hay claims temporales
    if exp is None and nbf is None and iat is None:
        respuesta["estado"] = "sin_claims"
        respuesta["detalle"].append("El payload no contiene claims de tiempo.")
        return respuesta

    # ----- VALIDACIÓN EXP -----
    if exp is not None:
        try:
            exp = int(exp)
            respuesta["fecha_exp"] = convertir_fecha(exp)
            if ahora > exp:
                respuesta["estado"] = "expirado"
                respuesta["detalle"].append("El token está expirado (exp).")
        except:
            respuesta["estado"] = "error"
            respuesta["detalle"].append("exp no es un número válido.")
            respuesta["fecha_exp"] = "⚠️ Valor inválido"

    # ----- VALIDACIÓN NBF -----
    if nbf is not None:
        try:
            nbf = int(nbf)
            respuesta["fecha_inicio"] = convertir_fecha(nbf)
            if ahora < nbf:
                respuesta["estado"] = "no_activo"
                respuesta["detalle"].append("El token aún no está activo (nbf).")
        except:
            respuesta["estado"] = "error"
            respuesta["detalle"].append("nbf no es un número válido.")
            respuesta["fecha_inicio"] = "⚠️ Valor inválido"

    # ----- VALIDACIÓN IAT -----
    if iat is not None:
        try:
            iat = int(iat)
            respuesta["fecha_emision"] = convertir_fecha(iat)
        except:
            respuesta["estado"] = "error"
            respuesta["detalle"].append("iat no es un número válido.")
            respuesta["fecha_emision"] = "⚠️ Valor inválido"

    # Si no fue expirado, ni no_activo, ni error → es válido
    if respuesta["estado"] is None:
        respuesta["estado"] = "valido"

    return respuesta



def generar_tabla_simbolos(header, payload):
    tabla = []

    if isinstance(header, dict):
        for clave, valor in header.items():
            tabla.append({
                "componente": "HEADER",
                "nombre": clave,
                "tipo": type(valor).__name__,
                "valor": valor
            })

    if isinstance(payload, dict):
        for clave, valor in payload.items():
            tabla.append({
                "componente": "PAYLOAD",
                "nombre": clave,
                "tipo": type(valor).__name__,
                "valor": valor
            })

    return tabla
