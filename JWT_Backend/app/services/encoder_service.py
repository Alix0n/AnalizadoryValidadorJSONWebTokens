"""
app/services/encoder_service.py

Fase 5: Codificación de JSON Web Tokens (JWT)
Implementación de JWTEncoder (HS256/HS384/HS512) + Base64URL + JSON serializer.
"""

import json
import base64
import hmac
import hashlib
import time
from typing import Dict, Any, Optional
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
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
        return alg_map[algorithm]

    @staticmethod
    def is_supported(algorithm: str) -> bool:
        return algorithm in ('HS256', 'HS384', 'HS512')


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
        padding = 4 - (len(b64_url) % 4)
        if padding != 4:
            b64_url += '=' * padding
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
# Signature generator (HMAC)
# -----------------------------
class SignatureGenerator:
    @staticmethod
    def generate(message: str, secret: str, algorithm: str) -> bytes:
        if not SignatureAlgorithm.is_supported(algorithm):
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
        hash_func = SignatureAlgorithm.get_hash_function(algorithm)
        return hmac.new(secret.encode('utf-8'), message.encode('utf-8'), digestmod=hash_func).digest()

    @staticmethod
    def generate_base64url(message: str, secret: str, algorithm: str) -> str:
        sig = SignatureGenerator.generate(message, secret, algorithm)
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


# -----------------------------
# JWT Encoder
# -----------------------------
class JWTEncoder:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def encode(
        self,
        payload: Dict[str, Any],
        secret: str,
        algorithm: str = 'HS256',
        header: Optional[Dict[str, Any]] = None,
        add_iat: bool = True
    ) -> JWTEncodeResult:
        self.errors = []
        self.warnings = []

        try:
            # Validate algorithm
            if not SignatureAlgorithm.is_supported(algorithm):
                err = f"Algoritmo no soportado: {algorithm}"
                self.errors.append(err)
                return JWTEncodeResult("", header or {}, payload, "", algorithm, False, err)

            # Build header
            if header is None:
                header = {"alg": algorithm, "typ": "JWT"}
            else:
                header = dict(header)  # shallow copy
                header["alg"] = algorithm
                if "typ" not in header:
                    header["typ"] = "JWT"

            # Add iat if requested
            if add_iat and 'iat' not in payload:
                payload = dict(payload)  # copy to avoid mutating caller
                payload['iat'] = int(time.time())

            # Serialize
            header_json = JSONSerializer.serialize(header)
            payload_json = JSONSerializer.serialize(payload)

            # Base64URL encode
            header_b64 = Base64URLEncoder.encode_string(header_json)
            payload_b64 = Base64URLEncoder.encode_string(payload_json)

            # Message to sign
            message = f"{header_b64}.{payload_b64}"

            # Signature
            signature_b64 = SignatureGenerator.generate_base64url(message, secret, algorithm)

            # Full token
            jwt_token = f"{message}.{signature_b64}"

            return JWTEncodeResult(jwt=jwt_token,
                                   header=header,
                                   payload=payload,
                                   signature=signature_b64,
                                   algorithm=algorithm,
                                   success=True)
        except Exception as e:
            err = f"Error al codificar JWT: {str(e)}"
            self.errors.append(err)
            return JWTEncodeResult(jwt="", header=header or {}, payload=payload,
                                   signature="", algorithm=algorithm, success=False, error=err)

    def encode_with_expiration(self, payload: Dict[str, Any], secret: str, expires_in_seconds: int = 3600, algorithm: str = 'HS256') -> JWTEncodeResult:
        payload = dict(payload)
        now = int(time.time())
        payload['iat'] = now
        payload['exp'] = now + int(expires_in_seconds)
        return self.encode(payload, secret, algorithm, add_iat=False)
