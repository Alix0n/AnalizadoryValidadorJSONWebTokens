from app.services.lexer_service import TokenType

class JWTParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
        self.errores = []
        self.arbol = {}
        self.producciones_usadas = []
        self.derivaciones = []

    def _actual(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _coincide(self, tipo, produccion):
        token = self._actual()
        if token and token.tipo == tipo:
            self.pos += 1
            self.producciones_usadas.append(produccion)
            return token
        else:
            if token:
                self.errores.append(f"Se esperaba {tipo.value}, pero se encontró {token.tipo.value}")
            else:
                self.errores.append(f"Se esperaba {tipo.value}, pero no hay más tokens")
            self.producciones_usadas.append(produccion + " (fallida)")
            return None

    # --- Símbolos no terminales ---
    def S(self):
        """S → H"""
        self.derivaciones.append("S ⇒ H")  # Pre-order: agregamos antes de procesar H
        nodo_h = self.H()
        return {"S": nodo_h}

    def H(self):
        """
        H → HEADER_B64 '.' P
        """
        token_header = self._coincide(TokenType.HEADER_B64, "H → HEADER_B64 . P")
        token_dot = self._coincide(TokenType.DOT, "H → HEADER_B64 . P")

        # Agregamos derivación antes de procesar P
        deriv = f"H ⇒ {token_header.valor if token_header else '?'} {'.' if token_dot else '?'} P"
        self.derivaciones.append(deriv)

        nodo_p = self.P() if token_dot else None
        return {
            "H": {
                "HEADER_B64": token_header.valor if token_header else None,
                "DOT": "." if token_dot else None,
                "P": nodo_p
            }
        }

    def P(self):
        """
        P → PAYLOAD_B64 '.' G
        """
        token_payload = self._coincide(TokenType.PAYLOAD_B64, "P → PAYLOAD_B64 . G")
        token_dot = self._coincide(TokenType.DOT, "P → PAYLOAD_B64 . G")

        # Agregamos derivación antes de procesar G
        deriv = f"P ⇒ {token_payload.valor if token_payload else '?'} {'.' if token_dot else '?'} G"
        self.derivaciones.append(deriv)

        nodo_g = self.G() if token_dot else None
        return {
            "P": {
                "PAYLOAD_B64": token_payload.valor if token_payload else None,
                "DOT": "." if token_dot else None,
                "G": nodo_g
            }
        }

    def G(self):
        """G → SIGNATURE_B64"""
        token_signature = self._coincide(TokenType.SIGNATURE_B64, "G → SIGNATURE_B64")
        deriv = f"G ⇒ {token_signature.valor if token_signature else '?'}"
        self.derivaciones.append(deriv)
        return {"G": {"SIGNATURE_B64": token_signature.valor if token_signature else None}}

    # --- Parseo principal ---
    def parsear(self):
        self.arbol = self.S()
        token_final = self._actual()
        if token_final and token_final.tipo != TokenType.EOF:
            self.errores.append("Tokens extra después de SIGNATURE")
        return len(self.errores) == 0

    def generar_arbol(self):
        return self.arbol

    def mostrar_producciones(self):
        return self.producciones_usadas

    def mostrar_derivaciones(self):
        return self.derivaciones
