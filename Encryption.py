import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def Key_Gen():
    #Generate the public/private key pair
    private_key = rsa.generate_private_key(
        public_exponent = 65537, 
        key_size = 4096, 
        backend = default_backend(),
    )
    
    # Save the private key to a file
    with open('private.key', 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption(),
            )
        )
        
    # Save the public key to a file    
    with open('a.pem', 'wb') as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo,
            )    
        )

def Signing():
    # Load the private key
    with open('private.key', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend(),
        )
        
    # Load the contents of the file to be signed
    with open('payload.dat', 'rb') as f:
        payload = f.read()
    
    # Sign the payload file
    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )
    with open('signature.sig', 'wb') as f:
        f.write(signature)
        
def Verification():
    # Load the public key.
    with open('a.pem', 'rb') as f:
        public_key = load_pem_public_key(f.read(), default_backend())
        
    # Load the pauload contents and the signature 
    with open('payload.dat', 'rb') as f:
        payload_contents = f.read()
    with open('signature.sig', 'rb') as f:
        signature = base64.b64encode(f.read())

    # Perform the verifivation
    try:
        public_key.verify(
            signature,
            payload_contents,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256,
        )        
    except cryptography.exceptions.InvalidSignature as e:
        print('ERROR: Payload and/or signature files failed verification')
        
Key_Gen()
Signing()
Verification()
    
