from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["jwt_analyzer"]
test_cases = db["test_cases"]

def guardar_resultado(descripcion, token, resultado):
    doc = {
        "token": token,
        "descripcion": descripcion,
        "resultado": resultado
    }
    test_cases.insert_one(doc)


print("Conectado a Mongo Atlas:", db)