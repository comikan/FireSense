#!/usr/bin/env python3
from flask import Flask, request, jsonify
import hashlib
from functools import wraps

app = Flask(__name__)
API_VERSION = "v1"
SECRET_KEY = os.getenv("FIRESENSE_SECRET")

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get('X-API-Key') != SECRET_KEY:
            return jsonify(error="Unauthorized"), 401
        return f(*args, **kwargs)
    return wrapper

@app.route(f"/{API_VERSION}/upload", methods=["POST"])
@auth_required
def upload():
    file = request.files['file']
    file_hash = hashlib.sha256(file.read()).hexdigest()
    return jsonify(hash=file_hash, size=len(file.read()))

@app.route(f"/{API_VERSION}/metadata/<file_id>")
@auth_required
def get_metadata(file_id):
    return jsonify({"id": file_id, "status": "stored"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
