from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization

# Generar clave RSA
def generar_clave_rsa():
    clave_privada_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return clave_privada_rsa

# Generar clave DSA
def generar_clave_dsa():
    clave_privada_dsa = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend()
    )
    return clave_privada_dsa

# Serializar la clave para visualización
def serializar_clave(clave_privada):
    clave_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return clave_pem.decode()

# Generar y mostrar las claves
clave_privada_rsa = generar_clave_rsa()
clave_privada_dsa = generar_clave_dsa()

print("Clave RSA:")
print(serializar_clave(clave_privada_rsa))

print("\nClave DSA:")
print(serializar_clave(clave_privada_dsa))
