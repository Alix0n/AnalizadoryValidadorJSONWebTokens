"""
app/services/encoder_service.py

Versión simplificada: usa PyJWT para crear y verificar JWT (HS256/HS384/HS512).
Se eliminó soporte RSA/cryptography para mantener la base usando únicamente PyJWT.
"""

import json
import base64
import hmac
import hashlib
import time
import jwt  # PyJWT
from typing import Dict, Any, Optional, Union, Tuple, List
from dataclasses import dataclass
from enum import Enum

# -----------------------------
# Signature algorithm helpers
# -----------------------------
class SignatureAlgorithm(Enum):
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"

    @staticmethod
    def get_hash_function(algorithm: str):
        alg_map = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        if algorithm not in alg_map:
            raise ValueError(f"Algoritmo no soportado para HMAC: {algorithm}")
        return alg_map[algorithm]

    @staticmethod
    def is_supported(algorithm: str) -> bool:
        return algorithm in ('HS256', 'HS384', 'HS512')

    @staticmethod
    def is_symmetric(algorithm: str) -> bool:
        return algorithm.startswith('HS')


# -----------------------------
# Base64URL encoder/decoder
# -----------------------------
class Base64URLEncoder:
    @staticmethod
    def encode(data: bytes) -> str:
        b64 = base64.urlsafe_b64encode(data).decode('utf-8')
        return b64.rstrip('=')

    @staticmethod
    def encode_string(text: str) -> str:
        return Base64URLEncoder.encode(text.encode('utf-8'))

    @staticmethod
    def decode(b64_url: str) -> bytes:
        remainder = len(b64_url) % 4
        if remainder:
            b64_url += '=' * (4 - remainder)
        return base64.urlsafe_b64decode(b64_url)

    @staticmethod
    def decode_string(b64_url: str) -> str:
        return Base64URLEncoder.decode(b64_url).decode('utf-8')


# -----------------------------
# JSON serializer (compact)
# -----------------------------
class JSONSerializer:
    @staticmethod
    def serialize(obj: Dict[str, Any]) -> str:
        return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)

    @staticmethod
    def deserialize(json_string: str) -> Dict[str, Any]:
        return json.loads(json_string)

    @staticmethod
    def validate_json(json_string: str) -> bool:
        try:
            json.loads(json_string)
            return True
        except Exception:
            return False


# -----------------------------
# Secret Key Manager
# -----------------------------
class SecretKeyManager:
    """Validación básica de claves secretas HMAC"""

    @staticmethod
    def validate_secret_key(secret: str, min_length: int = 32) -> Tuple[bool, Optional[str]]:
        if not secret:
            return False, "La clave secreta no puede estar vacía"
        if len(secret) < min_length:
            return False, f"La clave secreta debe tener al menos {min_length} caracteres"
        has_upper = any(c.isupper() for c in secret)
        has_lower = any(c.islower() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        has_special = any(not c.isalnum() for c in secret)
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        if complexity_score < 3:
            return False, "La clave debe contener al menos 3 de: mayúsculas, minúsculas, números, caracteres especiales"
        return True, None


# -----------------------------
# Signature generator (HMAC only)
# -----------------------------
class SignatureGenerator:
    @staticmethod
    def generate_hmac(message: str, secret: str, algorithm: str) -> bytes:
        if not SignatureAlgorithm.is_symmetric(algorithm):
            raise ValueError(f"Algoritmo {algorithm} no es simétrico (HMAC)")
        hash_func = SignatureAlgorithm.get_hash_function(algorithm)
        return hmac.new(secret.encode('utf-8'), message.encode('utf-8'), digestmod=hash_func).digest()

    @staticmethod
    def generate_base64url(message: str, secret: str, algorithm: str) -> str:
        sig = SignatureGenerator.generate_hmac(message, secret, algorithm)
        return Base64URLEncoder.encode(sig)


# -----------------------------
# Result dataclass
# -----------------------------
@dataclass
class JWTEncodeResult:
    jwt: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    success: bool
    error: Optional[str] = None
    warnings: List[str] = None
    method: str = "pyjwt"

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


# -----------------------------
# JWT Encoder (PyJWT-only)
# -----------------------------
class JWTEncoder:
    def __init__(self, validate_secret: bool = True):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.validate_secret = validate_secret

    def encode(
        self,
        payload: Dict[str, Any],
        secret: str,
        algorithm: str = 'HS256',
        header: Optional[Dict[str, Any]] = None,
        add_iat: bool = True
    ) -> JWTEncodeResult:
        """
        Codifica un JWT usando PyJWT (solo HS*)
        """
        self.errors = []
        self.warnings = []

        try:
            if not SignatureAlgorithm.is_supported(algorithm):
                err = f"Algoritmo no soportado: {algorithm}"
                self.errors.append(err)
                return JWTEncodeResult("", header or {}, payload, "", algorithm, False, err, method="pyjwt")

            if self.validate_secret and SignatureAlgorithm.is_symmetric(algorithm):
                is_valid, error_msg = SecretKeyManager.validate_secret_key(secret)
                if not is_valid:
                    self.warnings.append(f"⚠️ Advertencia de seguridad: {error_msg}")

            payload_copy = dict(payload)
            if add_iat and 'iat' not in payload_copy:
                payload_copy['iat'] = int(time.time())

            jwt_token = jwt.encode(payload_copy, secret, algorithm=algorithm, headers=header)

            # PyJWT v1.x -> bytes, v2.x -> str
            if isinstance(jwt_token, bytes):
                jwt_token = jwt_token.decode('utf-8')

            parts = jwt_token.split('.')
            header_decoded = jwt.get_unverified_header(jwt_token)

            return JWTEncodeResult(
                jwt=jwt_token,
                header=header_decoded,
                payload=payload_copy,
                signature=parts[2] if len(parts) == 3 else "",
                algorithm=algorithm,
                success=True,
                warnings=self.warnings,
                method="pyjwt"
            )

        except Exception as e:
            err = f"Error al codificar JWT: {str(e)}"
            self.errors.append(err)
            return JWTEncodeResult("", header or {}, payload, "", algorithm, False, err, method="pyjwt")

    def encode_with_expiration(self, payload: Dict[str, Any], secret: str, expires_in_seconds: int = 3600, algorithm: str = 'HS256') -> JWTEncodeResult:
        payload = dict(payload)
        now = int(time.time())
        payload['iat'] = now
        payload['exp'] = now + int(expires_in_seconds)
        return self.encode(payload, secret, algorithm, add_iat=False)

    def decode_and_verify(self, token: str, secret: str, algorithms: Optional[List[str]] = None, verify: bool = True) -> Dict[str, Any]:
        if algorithms is None:
            algorithms = ['HS256', 'HS384', 'HS512']

        try:
            decoded = jwt.decode(token, secret, algorithms=algorithms, options={"verify_signature": verify})
            return {"success": True, "payload": decoded}
        except jwt.ExpiredSignatureError:
            return {"success": False, "error": "El token ha expirado"}
        except jwt.InvalidSignatureError:
            return {"success": False, "error": "Firma inválida"}
        except jwt.InvalidTokenError as e:
            return {"success": False, "error": f"Token inválido: {str(e)}"}
