from pymongo import MongoClient
import os, certifi

from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

CA_FILE = certifi.where()
print("Usando certificado:", CA_FILE)

try:
    client = MongoClient(MONGO_URI, tls=True, tlsCAFile=CA_FILE, serverSelectionTimeoutMS=20000)
    db = client["jwt_analyzer"]
    print("✅ Conexión exitosa a MongoDB Atlas")
    print("Colecciones disponibles:", db.list_collection_names())
except Exception as e:
    print("❌ Error al conectar:", e)
