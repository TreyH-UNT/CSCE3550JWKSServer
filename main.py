from flask import Flask, jsonify, request, abort
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import time
import uuid
import base64

app = Flask(__name__)

# Key management
keys = []


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    expiry = time.time() + 3600  # 1-hour expiry time
    keys.append({
        "kid": kid,
        "private_key": private_key,
        "public_key": public_key,
        "expiry": expiry
    })


generate_key_pair()


# Convert integer to base64 URL encoded string
def int_to_base64url(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')


# JWT issuance
@app.route('/auth', methods=['POST'])
def auth():
    if request.method != 'POST':
        abort(405)

    key_to_use = None

    if 'expired' in request.args:
        key_to_use = next((key for key in keys if time.time() > key["expiry"]), None)
        if not key_to_use:
            generate_key_pair()
            key_to_use = keys[-1]
    else:
        key_to_use = next((key for key in keys if time.time() <= key["expiry"]), None)

    if not key_to_use:
        return jsonify({"error": "No keys available"}), 500

    encoded_token = jwt.encode({"user": "test", "exp": key_to_use["expiry"]}, key_to_use["private_key"],
                               algorithm="RS256", headers={"kid": key_to_use["kid"]})
    return jsonify({"token": encoded_token.decode('utf-8')})


# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method != 'GET':
        abort(405)
    return jsonify({
        "keys": [
            {
                "kty": "RSA",
                "kid": key["kid"],
                "use": "sig",
                "n": int_to_base64url(key["public_key"].public_numbers().n),
                "e": int_to_base64url(key["public_key"].public_numbers().e)
            } for key in keys if time.time() <= key["expiry"]
        ]
    })


if __name__ == "__main__":
    app.run(port=8080)
