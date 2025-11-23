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

    # ⚠️ NUEVAS REGLAS
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

    ahora = int(datetime.utcnow().timestamp())

    exp = payload.get("exp")
    nbf = payload.get("nbf")  # Ignorado si no existe
    iat = payload.get("iat")

    respuesta = {
        "estado": "sin_claims",
        "detalle": [],
        "fecha_actual": ahora,
        "fecha_exp": exp if exp is not None else None,
        "fecha_inicio": nbf if nbf is not None else None,
        "fecha_emision": iat if iat is not None else None
    }

    # Si no hay claims temporales
    if exp is None and nbf is None and iat is None:
        respuesta["detalle"].append("El payload no contiene claims de tiempo.")
        return respuesta

    respuesta["estado"] = "valido"

    # ----- VALIDACIÓN EXP -----
    if exp is not None:
        try:
            exp = int(exp)
            respuesta["fecha_exp"] = exp
            if ahora > exp:
                respuesta["estado"] = "expirado"
                respuesta["detalle"].append("El token está expirado (exp).")
        except:
            respuesta["estado"] = "error"
            respuesta["detalle"].append("exp no es un número válido.")

    # ----- VALIDACIÓN NBF -----
    # Aunque nbf ya no es obligatorio, sí se valida si existe
    if nbf is not None:
        try:
            nbf = int(nbf)
            respuesta["fecha_inicio"] = nbf
            if ahora < nbf:
                respuesta["estado"] = "no_activo"
                respuesta["detalle"].append("El token aún no está activo (nbf).")
        except:
            respuesta["estado"] = "error"
            respuesta["detalle"].append("nbf no es un número válido.")

    # ----- VALIDACIÓN IAT -----
    if iat is not None:
        try:
            iat = int(iat)
            respuesta["fecha_emision"] = iat
        except:
            respuesta["estado"] = "error"
            respuesta["detalle"].append("iat no es un número válido.")

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
