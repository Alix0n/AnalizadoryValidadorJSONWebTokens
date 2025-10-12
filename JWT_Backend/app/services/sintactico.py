from app.services.lexer_service import TokenType

class JWTParser:
    """
    Analizador sintáctico simple basado en una gramática libre de contexto.
    GLC:
        <JWT> → <HEADER_B64> '.' <PAYLOAD_B64> '.' <SIGNATURE_B64>
    """

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
        self.errores = []

    def _actual(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _coincide(self, tipo):
        token = self._actual()
        if token and token.tipo == tipo:
            self.pos += 1
            return True
        else:
            if token:
                self.errores.append(f"Se esperaba {tipo.value}, pero se encontró {token.tipo.value}")
            else:
                self.errores.append(f"Se esperaba {tipo.value}, pero no hay más tokens")
            return False

    def parsear(self):
        """
        Valida si la secuencia de tokens cumple la estructura de un JWT.
        """
        if not self._coincide(TokenType.HEADER_B64):
            return False
        if not self._coincide(TokenType.DOT):
            return False
        if not self._coincide(TokenType.PAYLOAD_B64):
            return False
        if not self._coincide(TokenType.DOT):
            return False
        if not self._coincide(TokenType.SIGNATURE_B64):
            return False
        if self._actual() and self._actual().tipo != TokenType.EOF:
            self.errores.append("Tokens extra después del SIGNATURE")
            return False
        return True

    def generar_arbol(self):
        """
        Devuelve un árbol sintáctico simple en formato dict.
        """
        return {
            "JWT": {
                "HEADER": "HEADER_B64",
                "DOT1": ".",
                "PAYLOAD": "PAYLOAD_B64",
                "DOT2": ".",
                "SIGNATURE": "SIGNATURE_B64"
            }
        }
