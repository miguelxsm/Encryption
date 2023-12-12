from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from sympy import randprime, mod_inverse

# Función para generar dos números primos grandes
def generar_primos(tamano_bits):
    primo1 = randprime(2**(tamano_bits - 1), 2**tamano_bits)
    primo2 = randprime(2**(tamano_bits - 1), 2**tamano_bits)
    return primo1, primo2

# Generar claves RSA a partir de números primos
def generar_clave_rsa_con_primos(primo1, primo2):
    e = 65537
    n = primo1 * primo2
    phi = (primo1 - 1) * (primo2 - 1)
    d = mod_inverse(e, phi)
    dmp1 = d % (primo1 - 1)
    dmq1 = d % (primo2 - 1)
    iqmp = mod_inverse(primo2, primo1)

    clave_privada_rsa = rsa.RSAPrivateNumbers(
        p=primo1,
        q=primo2,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(
            e=e,
            n=n
        )
    ).private_key(default_backend())
    return clave_privada_rsa

# Generar clave DSA
def generar_clave_dsa():
    clave_privada_dsa = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend()
    )
    return clave_privada_dsa

# Generar números primos y claves
tamano_bits_primos = 1024  # La mitad del tamaño de la clave RSA
primo1, primo2 = generar_primos(tamano_bits_primos)
clave_privada_rsa = generar_clave_rsa_con_primos(primo1, primo2)
clave_privada_dsa = generar_clave_dsa()

print("Primer primo para RSA:", primo1)
print("Segundo primo para RSA:", primo2)
print("\nClave privada RSA:", clave_privada_rsa)
print("\nClave privada DSA:", clave_privada_dsa)
