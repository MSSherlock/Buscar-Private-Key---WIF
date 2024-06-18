# Buscar-Private-Key---WIF

Informacion detallada del script:

Este script es una herramienta para generar claves privadas y sus correspondientes direcciones Bitcoin. Utiliza las bibliotecas ecdsa para generar las claves y base58 para codificar y decodificar las claves en formato Wallet Import Format (WIF). También utiliza las funciones de hash SHA256 y RIPEMD160 del módulo Crypto.Hash para generar las direcciones Bitcoin. A continuación, se explica cada parte del script en detalle:


Importación de módulos: Se importan los módulos y funciones necesarios para el script.

    import ecdsa
    import base58
    from Crypto.Hash import SHA256, RIPEMD160
    import random


Función private_key_to_wif: Esta función toma una clave privada en formato binario y la convierte en formato Wallet Import Format (WIF).

    def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key
    sha256_1 = SHA256.new(extended_key)
    sha256_2 = SHA256.new(sha256_1.digest())
    checksum = sha256_2.digest()[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')


Función generate_address: Esta función toma una clave privada en formato binario y genera la dirección Bitcoin correspondiente.

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


Entrada del usuario: El script solicita al usuario que ingrese el número de claves privadas que desea generar y el nombre del archivo de salida.

    num_keys = int(input("Ingrese el número de claves privadas que desea generar: "))
    output_filename = input("Ingrese el nombre del archivo de salida (ej: keys.txt): ")


Generación de claves y direcciones: El script genera las claves privadas y sus correspondientes direcciones Bitcoin hasta que se hayan generado el número deseado de claves únicas. Las claves y direcciones se imprimen en la consola y se guardan en un archivo de texto.

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


En resumen, el script genera claves privadas únicas, las convierte al formato WIF y genera las direcciones Bitcoin correspondientes. Luego, imprime las claves y direcciones en la consola y las guarda en un archivo de texto especificado por el usuario.



TURORIAL


Paso 1: Instalar Python3

    sudo apt install python3


Paso 2: Instalar las dependencias

El script requiere las siguientes bibliotecas de Python: 

    pip install ecdsa
    pip install base58
    pip install pycryptodome


Paso 3: Guardar el script:

    git clone https://github.com/MSSherlock/Buscar-Private-Key---WIF.git

Ubicar el script y abrirlo en una terminal, para ejecutar usar:

    python3 Buscar-Private-Key-WIF.py





Gracias por usar este Script! :) 

Donaciones en Bitcoin: bc1qpwuvp6nacke0h0krgmnydc9nht4v3h2qqd8ck6
