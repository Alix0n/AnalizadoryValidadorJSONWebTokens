import re
import base64
import json
from enum import Enum
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

# 1. DEFINICIÓN DEL ALFABETO
class Alfabeto:

    # Alfabeto Base64URL (64 caracteres)
    BASE64URL_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
    
    # Delimitador JWT
    DELIMITADOR = '.'
    
    # Alfabeto completo JWT
    JWT_CHARS = BASE64URL_CHARS | {DELIMITADOR}
    
    # Alfabeto JSON (después de decodificar)
    JSON_ESTRUCTURALES = {'{', '}', '[', ']', ':', ','}
    JSON_DELIMITADORES = {'"'}
    JSON_ESPACIOS = {' ', '\t', '\n', '\r'}
    
    @staticmethod
    def es_base64url(caracter: str) -> bool:
        """Verifica si un carácter pertenece al alfabeto Base64URL."""
        return caracter in Alfabeto.BASE64URL_CHARS
    
    @staticmethod
    def es_delimitador(caracter: str) -> bool:
        """Verifica si un carácter es el delimitador JWT."""
        return caracter == Alfabeto.DELIMITADOR
    
    @staticmethod
    def describir_alfabeto() -> str:
        """Retorna una descripción del alfabeto."""
        return (
        "ALFABETO BASE64URL:\n"
        "  - Letras mayúsculas: A-Z (26 caracteres)\n"
        "  - Letras minúsculas: a-z (26 caracteres)\n"
        "  - Dígitos: 0-9 (10 caracteres)\n"
        "  - Símbolos: - _ (2 caracteres)\n"
        "  Total: 64 caracteres\n\n"
        "DELIMITADOR JWT:\n"
        "  - Punto: . (1 carácter)\n\n"
        "ALFABETO TOTAL JWT:\n"
        "  - Base64URL + Delimitador = 65 caracteres\n"
    )

# 2. TIPOS DE TOKENS

class TokenType(Enum):
    HEADER_B64 = "HEADER_B64"         
    PAYLOAD_B64 = "PAYLOAD_B64"        
    SIGNATURE_B64 = "SIGNATURE_B64"    
    DOT = "DOT"                        
    EOF = "EOF"                        # Fin de entrada
    ERROR = "ERROR"                    # Error léxico


@dataclass
class Token:
    tipo: TokenType
    valor: str
    posicion: int
    linea: int = 1
    columna: int = 0
    
    def __str__(self) -> str:
        valor_corto = self.valor[:30] + "..." if len(self.valor) > 30 else self.valor
        return f"Token({self.tipo.value}, '{valor_corto}', pos={self.posicion}, col={self.columna})"
    
    def to_dict(self) -> dict:
        """Convierte el token a diccionario."""
        return {
            'tipo': self.tipo.value,
            'valor': self.valor,
            'posicion': self.posicion,
            'linea': self.linea,
            'columna': self.columna,
            'longitud': len(self.valor)
        }

# 3. DECODIFICADOR BASE64URL

class Base64URLDecoder:
    @staticmethod
    def decodificar(cadena_b64: str) -> Optional[str]:
        """
        Decodifica una cadena Base64URL a texto UTF-8.
        """
        try:
            # Agregar padding si es necesario
            padding = 4 - (len(cadena_b64) % 4)
            if padding and padding != 4:
                cadena_b64 += '=' * padding
            
            # Convertir Base64URL a Base64 estándar
            cadena_b64_std = cadena_b64.replace('-', '+').replace('_', '/')
            
            # Decodificar
            bytes_decodificados = base64.b64decode(cadena_b64_std)
            return bytes_decodificados.decode('utf-8')
            
        except Exception as e:
            return None
    
    @staticmethod
    def codificar(texto: str) -> str:
        """
        Codifica un texto a Base64URL.
        """
        # Codificar a bytes
        bytes_texto = texto.encode('utf-8')
        
        # Codificar a Base64 estándar
        b64_std = base64.b64encode(bytes_texto).decode('utf-8')
        
        # Convertir a Base64URL (remover padding y reemplazar caracteres)
        b64_url = b64_std.rstrip('=').replace('+', '-').replace('/', '_')
        
        return b64_url

# 4. ANALIZADOR LÉXICO PRINCIPAL


class JWTLexer:
    """
    Analizador Léxico para JSON Web Tokens.
    
    Realiza:
    1. Tokenización de la estructura JWT
    2. Validación de caracteres Base64URL
    3. Identificación de delimitadores
    4. Decodificación Base64URL
    5. Análisis de estructura JSON
    """
    
    def __init__(self, jwt_string: str):
        """
        Inicializa el analizador léxico.
        
        Args:
            jwt_string: Cadena JWT a analizar
        """
        self.entrada = jwt_string.strip()
        self.tokens: List[Token] = []
        self.errores: List[str] = []
        self.advertencias: List[str] = []
        self.mensajes_json: List[str] = []


        
        # Componentes decodificados
        self.header_decodificado: Optional[Dict[str, Any]] = None
        self.payload_decodificado: Optional[Dict[str, Any]] = None
        self.signature_raw: Optional[str] = None
    
    def _validar_base64url(self, cadena: str) -> Tuple[bool, Optional[str]]:
        """
        Valida que una cadena solo contenga caracteres Base64URL.
        
        Args:
            cadena: Cadena a validar
            
        Returns:
            (es_valida, primer_caracter_invalido)
        """
        for i, char in enumerate(cadena):
            if not Alfabeto.es_base64url(char):
                return False, char
        return True, None
    
    def _crear_token(self, tipo: TokenType, valor: str, posicion: int, 
                     columna: int) -> Token:
        """Crea un token con los parámetros dados."""
        return Token(tipo, valor, posicion, 1, columna)
    
    def tokenizar(self) -> List[Token]:
        """
        Realiza la tokenización completa del JWT.
        
        Pasos:
        1. Validar estructura básica (3 partes separadas por '.')
        2. Validar caracteres Base64URL en cada parte
        3. Crear tokens para cada componente
        4. Agregar token EOF
        
        Returns:
            Lista de tokens identificados
        """
        print("=" * 70)
        print("INICIANDO ANÁLISIS LÉXICO")
        print("=" * 70)
        print(f"\nEntrada: {self.entrada[:60]}{'...' if len(self.entrada) > 60 else ''}")
        print(f"Longitud: {len(self.entrada)} caracteres\n")
        
        # Validación inicial: entrada vacía
        if not self.entrada:
            self.errores.append("Error: Entrada vacía")
            self.tokens.append(self._crear_token(TokenType.ERROR, "", 0, 0))
            return self.tokens
        
        # Dividir por el delimitador
        partes = self.entrada.split('.')
        
        # Validar número de partes
        if len(partes) != 3:
            self.errores.append(
                f"Error estructural: JWT debe tener exactamente 3 partes "
                f"separadas por '.', encontradas {len(partes)} partes"
            )
            self.tokens.append(self._crear_token(TokenType.ERROR, self.entrada, 0, 0))
            return self.tokens
        
        header, payload, signature = partes
        posicion_actual = 0
        columna_actual = 0
        
        print("Estructura detectada:")
        print(f"  - HEADER:    {len(header)} caracteres")
        print(f"  - PAYLOAD:   {len(payload)} caracteres")
        print(f"  - SIGNATURE: {len(signature)} caracteres\n")
        
        # ==================================================================
        # TOKENIZAR HEADER
        # ==================================================================
        print("1. Analizando HEADER...")
        
        if not header:
            self.errores.append("Error: Header está vacío")
            self.tokens.append(self._crear_token(TokenType.ERROR, header, posicion_actual, columna_actual))
        else:
            es_valido, char_invalido = self._validar_base64url(header)
            
            if not es_valido:
                self.errores.append(
                    f"Error en HEADER (posición {posicion_actual}): "
                    f"Carácter inválido '{char_invalido}'"
                )
                self.tokens.append(self._crear_token(TokenType.ERROR, header, posicion_actual, columna_actual))
            else:
                self.tokens.append(self._crear_token(TokenType.HEADER_B64, header, posicion_actual, columna_actual))
                print(f"   ✓ HEADER válido: {header[:40]}{'...' if len(header) > 40 else ''}")
        
        posicion_actual += len(header)
        columna_actual += len(header)
        
        # Primer delimitador
        self.tokens.append(self._crear_token(TokenType.DOT, '.', posicion_actual, columna_actual))
        posicion_actual += 1
        columna_actual += 1
        
        # ==================================================================
        # TOKENIZAR PAYLOAD
        # ==================================================================
        print("\n2. Analizando PAYLOAD...")
        
        if not payload:
            self.errores.append("Error: Payload está vacío")
            self.tokens.append(self._crear_token(TokenType.ERROR, payload, posicion_actual, columna_actual))
        else:
            es_valido, char_invalido = self._validar_base64url(payload)
            
            if not es_valido:
                self.errores.append(
                    f"Error en PAYLOAD (posición {posicion_actual}): "
                    f"Carácter inválido '{char_invalido}'"
                )
                self.tokens.append(self._crear_token(TokenType.ERROR, payload, posicion_actual, columna_actual))
            else:
                self.tokens.append(self._crear_token(TokenType.PAYLOAD_B64, payload, posicion_actual, columna_actual))
                print(f"   ✓ PAYLOAD válido: {payload[:40]}{'...' if len(payload) > 40 else ''}")
        
        posicion_actual += len(payload)
        columna_actual += len(payload)
        
        # Segundo delimitador
        self.tokens.append(self._crear_token(TokenType.DOT, '.', posicion_actual, columna_actual))
        posicion_actual += 1
        columna_actual += 1
        
        # ==================================================================
        # TOKENIZAR SIGNATURE
        # ==================================================================
        print("\n3. Analizando SIGNATURE...")
        
        if not signature:
            self.errores.append("Error: Signature está vacía")
            self.tokens.append(self._crear_token(TokenType.ERROR, signature, posicion_actual, columna_actual))
        else:
            es_valido, char_invalido = self._validar_base64url(signature)
            
            if not es_valido:
                self.errores.append(
                    f"Error en SIGNATURE (posición {posicion_actual}): "
                    f"Carácter inválido '{char_invalido}'"
                )
                self.tokens.append(self._crear_token(TokenType.ERROR, signature, posicion_actual, columna_actual))
            else:
                self.tokens.append(self._crear_token(TokenType.SIGNATURE_B64, signature, posicion_actual, columna_actual))
                print(f"   ✓ SIGNATURE válida: {signature[:40]}{'...' if len(signature) > 40 else ''}")
        
        posicion_actual += len(signature)
        columna_actual += len(signature)
        
        # Token EOF
        self.tokens.append(self._crear_token(TokenType.EOF, '', posicion_actual, columna_actual))
        
        print(f"\n✓ Tokenización completada: {len(self.tokens)} tokens generados")
        
        return self.tokens
    
    def decodificar_componentes(self) -> bool:
        """
        Decodifica los componentes Base64URL del JWT.
        
        Returns:
            True si la decodificación fue exitosa
        """
        print("\n" + "=" * 70)
        print("DECODIFICANDO COMPONENTES BASE64URL")
        print("=" * 70 + "\n")
        
        # Buscar tokens de header y payload
        header_token = next((t for t in self.tokens if t.tipo == TokenType.HEADER_B64), None)
        payload_token = next((t for t in self.tokens if t.tipo == TokenType.PAYLOAD_B64), None)
        signature_token = next((t for t in self.tokens if t.tipo == TokenType.SIGNATURE_B64), None)
        
        exito = True
        
        # Decodificar HEADER
        if header_token:
            print("1. Decodificando HEADER...")
            header_texto = Base64URLDecoder.decodificar(header_token.valor)
            
            if header_texto:
                print(f"   Decodificado: {header_texto}")
                
                try:
                    self.header_decodificado = json.loads(header_texto)
                    mensaje = "✓ HEADER JSON válido"
                    self.mensajes_json.append(mensaje)
                    print("   " + mensaje)
                    print(f"   ✓ JSON válido")
                    print(f"   Estructura: {json.dumps(self.header_decodificado, indent=6)}")
                except json.JSONDecodeError as e:
                    mensaje = f"✗ HEADER JSON inválido: {str(e)}"
                    self.mensajes_json.append(mensaje)
                    self.errores.append(mensaje)
                    self.errores.append(f"Error: Header no es JSON válido - {str(e)}")
                    print(f"   ✗ Error de JSON: {str(e)}")
                    exito = False
            else:
                mensaje = "✗ Error: Header no se pudo decodificar (Base64URL inválido)"
                self.mensajes_json.append(mensaje)
                self.errores.append("Error: No se pudo decodificar el header")
                print("   ✗ Error en decodificación Base64URL")
                exito = False
        
        # Decodificar PAYLOAD
        if payload_token:
            print("\n2. Decodificando PAYLOAD...")
            payload_texto = Base64URLDecoder.decodificar(payload_token.valor)
            
            if payload_texto:
                print(f"   Decodificado: {payload_texto}")
                
                try:
                    self.payload_decodificado = json.loads(payload_texto)
                    mensaje = "✓ PAYLOAD JSON válido"
                    self.mensajes_json.append(mensaje)
                    print(f"   ✓ JSON válido")
                    print(f"   Estructura: {json.dumps(self.payload_decodificado, indent=6)}")
                except json.JSONDecodeError as e:
                    mensaje = f"✗ PAYLOAD JSON inválido: {str(e)}"
                    self.mensajes_json.append(mensaje)
                    self.errores.append(f"Error: Payload no es JSON válido - {str(e)}")
                    print(f"   ✗ Error de JSON: {str(e)}")
                    exito = False
            else:
                mensaje = "✗ Error: Payload no se pudo decodificar (Base64URL inválido)"
                self.mensajes_json.append(mensaje)
                self.errores.append("Error: No se pudo decodificar el payload")
                print("   ✗ Error en decodificación Base64URL")
                exito = False
        
        # Guardar SIGNATURE (no se decodifica, son bytes)
        if signature_token:
            print("\n3. SIGNATURE detectada")
            self.signature_raw = signature_token.valor
            print(f"   Base64URL: {self.signature_raw[:50]}{'...' if len(self.signature_raw) > 50 else ''}")
            print("   (La signature no se decodifica, permanece como bytes)")
        
        return exito
    
    def analizar_estructura_json(self):
        """
        Analiza la estructura JSON del header y payload decodificados.
        """
        print("\n" + "=" * 70)
        print("ANÁLISIS DE ESTRUCTURA JSON")
        print("=" * 70 + "\n")
        
        # Analizar HEADER
        if self.header_decodificado:
            print("HEADER - Estructura JSON:")
            print(f"  Tipo: {type(self.header_decodificado).__name__}")
            print(f"  Campos: {len(self.header_decodificado)}")
            
            for clave, valor in self.header_decodificado.items():
                print(f"    - {clave}: {valor} (tipo: {type(valor).__name__})")
            
            # Validar campos obligatorios
            if 'alg' not in self.header_decodificado:
                self.advertencias.append("Advertencia: Campo 'alg' no encontrado en header")
            
            if 'typ' not in self.header_decodificado:
                self.advertencias.append("Advertencia: Campo 'typ' no encontrado en header")
        
        # Analizar PAYLOAD
        if self.payload_decodificado:
            print("\nPAYLOAD - Estructura JSON:")
            print(f"  Tipo: {type(self.payload_decodificado).__name__}")
            print(f"  Campos (claims): {len(self.payload_decodificado)}")
            
            for clave, valor in self.payload_decodificado.items():
                print(f"    - {clave}: {valor} (tipo: {type(valor).__name__})")
    
    # En tu lexer_service.py - Método generar_reporte()

    def generar_reporte(self) -> str:
        """
        Genera un reporte textual del análisis léxico
        """
        reporte = []
        
        # Encabezado
        reporte.append(f"Entrada: {self.entrada[:50]}{'...' if len(self.entrada) > 50 else ''}")
        reporte.append(f"Longitud: {len(self.entrada)} caracteres")
        reporte.append("")
        
        # Estructura detectada
        reporte.append("Estructura detectada:")
        if len(self.tokens) >= 5:
            header_len = len(self.tokens[0].valor)
            payload_len = len(self.tokens[2].valor)
            signature_len = len(self.tokens[4].valor)
            
            reporte.append(f"  - HEADER:    {header_len} caracteres")
            reporte.append(f"  - PAYLOAD:   {payload_len} caracteres")
            reporte.append(f"  - SIGNATURE: {signature_len} caracteres")
        reporte.append("")
        
        # Análisis de componentes
        if len(self.tokens) > 0:
            reporte.append("1. Analizando HEADER...")
            header_val = self.tokens[0].valor
            reporte.append(f"   ✓ HEADER válido: {header_val[:36]}{'...' if len(header_val) > 36 else ''}")
            reporte.append("")
        
        if len(self.tokens) > 2:
            reporte.append("2. Analizando PAYLOAD...")
            payload_val = self.tokens[2].valor
            reporte.append(f"   ✓ PAYLOAD válido: {payload_val[:50]}{'...' if len(payload_val) > 50 else ''}")
            reporte.append("")
        
        if len(self.tokens) > 4:
            reporte.append("3. Analizando SIGNATURE...")
            sig_val = self.tokens[4].valor
            reporte.append(f"   ✓ SIGNATURE válida: {sig_val[:50]}{'...' if len(sig_val) > 50 else ''}")
            reporte.append("")
        
        if self.mensajes_json:
            reporte.append("✅ VALIDACIÓN DE JSON:")
            for msg in self.mensajes_json:
                reporte.append(f"   {msg}")
            reporte.append("")
            
        # Errores y advertencias
        if self.errores:
            reporte.append("❌ ERRORES DETECTADOS:")
            for err in self.errores:
                reporte.append(f"   • {err}")
            reporte.append("")
        
        if self.advertencias:
            reporte.append("⚠️ ADVERTENCIAS:")
            for adv in self.advertencias:
                reporte.append(f"   • {adv}")
            reporte.append("")
        
        # Resumen
        reporte.append(f"Total de tokens identificados: {len(self.tokens)}")
        
        return "\n".join(reporte)
    
    def tiene_errores(self) -> bool:
        """Verifica si hubo errores durante el análisis."""
        return len(self.errores) > 0



