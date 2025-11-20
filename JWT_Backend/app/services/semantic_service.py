import datetime

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
        return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "⚠️ Valor no convertible a fecha"

def analizar_payload_semantico(payload):
    errores = []
    claims_estandar = ["iss", "sub", "aud", "exp", "iat", "nbf"]
    tipos_correctos = {
        "iss": str,
        "sub": str,
        "aud": (str, list),
        "exp": int,
        "iat": int,
        "nbf": int
    }

    if not isinstance(payload, dict):
        return ["El payload no tiene formato JSON válido"]

    for claim in claims_estandar:
        if claim not in payload:
            errores.append(f"Claim estándar '{claim}' no encontrado en payload")
        else:
            valor = payload[claim]
            tipo_esperado = tipos_correctos[claim]
            if not isinstance(valor, tipo_esperado):
                errores.append(
                    f"Claim '{claim}' tiene tipo incorrecto (esperado {tipo_esperado.__name__}, recibido {type(valor).__name__})"
                )

    return errores


def validar_tiempo(payload):
    """Valida si el token está vigente según 'exp', 'iat', 'nbf' y devuelve fechas legibles"""
    if not isinstance(payload, dict):
        return {
            "estado": "❌ Payload inválido",
            "fecha_emision": None,
            "fecha_expiracion": None,
            "detalles": []
        }

    ahora = int(datetime.datetime.now().timestamp())
    fecha_actual = convertir_fecha(ahora)
    
    iat = payload.get("iat")
    exp = payload.get("exp")
    nbf = payload.get("nbf")

    fecha_iat = convertir_fecha(iat) if iat else "⚠️ No disponible"
    fecha_exp = convertir_fecha(exp) if exp else "⚠️ Token sin fecha de expiración"
    
    detalles = []

    if exp and ahora > exp:
        detalles.append("Token expirado")
    if iat and ahora < iat:
        detalles.append("Token emitido en el futuro")
    if nbf and ahora < nbf:
        detalles.append("Token aún no es válido (nbf futuro)")

    if not detalles:
        detalles.append("Token vigente y válido temporalmente")

    return {
        "estado": "✅ Token válido temporalmente" if not detalles[:-1] else "⚠️ Token con advertencias",
        "fecha_emision": fecha_iat,
        "fecha_expiracion": fecha_exp,
        "detalles": detalles,
        "fecha_actual": fecha_actual
    }


def generar_tabla_simbolos(header, payload):
    """Crea una tabla de símbolos con los campos del header y payload"""
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
