import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CSUIT = ""
cifra = ""
iv = os.urandom(16)
# Generate some parameters. These can be reused.
#parameters = dh.generate_parameters(generator=2, key_size=2048)

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def start_cifra(key):
    iv = os.urandom(16)
    alg,modo,dige = CSUIT.split("_")
    if(dige == "SHA256"):
        digest = hashes.Hash(hashes.SHA256())
    elif(dige == "SHA512"):
        digest = hashes.Hash(hashes.SHA512())
    elif(dige == "SHA3256"):
        digest = hashes.Hash(hashes.SHA3_256())
    elif(dige == "SHA3512"):
        digest = hashes.Hash(hashes.SHA3_512())
    if(modo == 'GCM'):
        mode = modes.GCM(iv)
    elif(modo == 'CFB'):
        mode = modes.CFB(iv)
    elif(modo == 'CBC'):
        mode = modes.CBC(iv)
    elif(modo == 'CTR'):
        mode = modes.CTR(iv)
    elif(modo == 'OFB'):
        mode = modes.OFB(iv)
    if(alg == 'AES'):
        algorithm = algorithms.AES(key)
    elif(alg == 'SEED'):
        algorithm = algorithms.SEED(key)
    elif(alg == 'CAST5'):
        algorithm = algorithms.CAST5(key)
    elif(alg == 'TripleDES'):
        algorithm = algorithms.TripleDES(key)
    elif(alg == 'Camellia'):
        algorithm = algorithms.Camellia(key)
    cifra = Cipher(algorithm,modo)

def cifrar(data):
    criptar = cifra.encryptor()
    cifrado = criptar.update(data.encode('latin')) + criptar.finalize()
    MAC = digest.update(cifrado) + digest.finalize()
    dict = {'data':cifrado,'MAC':MAC}
    return criptar.update(json.dumps(dict, indent=4).encode('latin')) + criptar.finalize()

def decifrar(data):
    MAClinha = digest.update(data['data']) + digest.finalize()
    if(MAClinha != data['MAC']):
        return "ERROR 500"

    decriptar = cifra.decryptor()
    decifrado = decriptar.update(data['data']) + decriptar.finalize()
    return decifrado.decode('latin')

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    #CSUIT negotiation
    algorithms = ['AES', 'SEED', 'CAST5', 'TripleDES', 'Camellia']
    modes = ['GCM', 'CFB', 'CBC', 'CTR', 'OFB']
    dg = ['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
    code = 0
    for alg in algorithms:
        for mod in modes:
            for dig in dg:
                message = alg + '_' + mod + '_' + dig
                posting = requests.post(f'{SERVER_URL}/api/csuit',data=message)
                code = posting.status_code
                if code == 200:
                    CSUIT = message
                    break
            if code == 200:
                break
        if code == 200:
            break
    if(code != 200):
        return
    """
    #key negotiation
    # Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()
    posting = requests.post(f'{SERVER_URL}/api/difhell',data=private_key.public_key())
    server_public_key = posting.text()
    shared_key = private_key.exchange(server_public_key)
    # Perform key derivation.
    derived_key = HKDF(
    algorithm = hashes.SHA256(),
    length = 32,
    salt = None,
    info = b'handshake data').derive(shared_key)
    #KEY para o resto da sessao
    #derived_key
    """
    # TODO: Secure the session

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()


    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break
    proc.stdin.close()
    proc.kill()
    proc.terminate()
if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)