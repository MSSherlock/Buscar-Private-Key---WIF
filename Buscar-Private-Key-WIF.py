import ecdsa
import base58
from Crypto.Hash import SHA256, RIPEMD160
import random

def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key
    sha256_1 = SHA256.new(extended_key)
    sha256_2 = SHA256.new(sha256_1.digest())
    checksum = sha256_2.digest()[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')

def generate_address(private_key):
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    public_key = signing_key.get_verifying_key()
    public_key_point = public_key.to_string('compressed')
    ripemd160 = RIPEMD160.new()
    ripemd160.update(SHA256.new(public_key_point).digest())
    public_key_hash = ripemd160.digest()
    version_byte = b'\x00'
    address = base58.b58encode(version_byte + public_key_hash + SHA256.new(SHA256.new(version_byte + public_key_hash).digest()).digest()[:4])
    return address.decode('utf-8')

num_keys = int(input("Ingrese el número de claves privadas que desea generar: "))
output_filename = input("Ingrese el nombre del archivo de salida (ej: keys.txt): ")

generated_keys = set()
key_counter = 0

with open(output_filename, 'w') as f:
    while len(generated_keys) < num_keys:
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        wif = private_key_to_wif(private_key.to_string())
        address = generate_address(private_key.to_string())

        if wif not in generated_keys:
            generated_keys.add(wif)
            key_counter += 1
            print(f"Clave privada (WIF) {key_counter}: {wif}")
            print(f"Dirección Bitcoin: {address}\n")

            f.write(f"{wif}\n")

    print(f"Se han generado {len(generated_keys)} claves privadas únicas.")
