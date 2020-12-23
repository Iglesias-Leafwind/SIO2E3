#TODO LIST CLIENT
"""
    done?31-Unique users id created from server
    done?2-Verification if already logged in (with flag)
    done?3-Bye server message
4-Arranjar global variables???
5-Mudar length da derivacao da key para criar 3 keys ao mesmo tempo 1 para criptar data outra para hmac e outra para mensagem
6-Set a todas mensagens para estarem criptadas com um hmac (a mensagem enviada com estes 2 tambem estara encriptada com uma 3 key)
7-Set a todos chunks com derivação das keys pela principal e por algo no ficheiro?
8-Escrever o protocolo de como isto tudo foi feito para o relatorio
NOTA a maneira como guardamos no cliente e no server as chaves usadas para cifrar vai ser diferente
"""
# TODO SERVER
"""
    done?1-Gerar um id para cada cliente
    done?2-Aceitar um hello e criar o cliente caso ele n esteja ja ligado se estiver n faz nada ou envia um hello de resposta para dizer que o user ja esta com uma sessao
    done?3-Quando receber bye message eleminar cliente
4-Gerar um iv no csuit e mandar ao cliente com o csuit
5-Criar dicionarios para guardar toda informação necessaria
6-No dicionario das keys vai estar por ordem (keyCifrarTudo,keyCifrarData,keyCifrarMac)
7-Arranjar global variables???
8-Set a todas mensagens para estarem criptadas de acordo com o uuid da pessoa e as suas keys
9-Derivaçao das chaves por chunk pelas keys e por algo no ficheiro
10-Escrever o protocolo de isto tudo para o relatorio
NOTA a maneira como guardamos no cliente e no server as chaves usadas para cifrar vai ser diferente
"""
#TODO NOTAS
"""
Fazer verificação de quanto é que um user ja viu
Encrypt then mac aka mac da cifra
Licenca por musica que o user so precisa de mostrar por leitura da musica depois de receber a licenca
Se a licenca acabar o user precisa pedir outra licenca / pede automaticamente
User vai mandar o seu CC como identificador de log in e o server envia um uuid para ele distinguir os users
Sintese chunk pelo id do chunk?

"""
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
from cryptography.hazmat.primitives import serialization

cookies = {'session_id': 'noID'}
CSUIT = ""
iv = os.urandom(16)
# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=512)

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def start_cifra(key):
    global iv
    global cifra
    global digest
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
    global cifra
    criptar = cifra.encryptor()
    cifrado = criptar.update(data.encode('latin')) + criptar.finalize()
    MAC = digest.update(cifrado) + digest.finalize()
    dict = {'data':cifrado,'MAC':MAC}
    return criptar.update(json.dumps(dict, indent=4).encode('latin')) + criptar.finalize()

def decifrar(data):
    global digest
    MAClinha = digest.update(data['data']) + digest.finalize()
    if(MAClinha != data['MAC']):
        return "ERROR 500"

    decriptar = cifra.decryptor()
    decifrado = decriptar.update(data['data']) + decriptar.finalize()
    return decifrado.decode('latin')

activesession = False
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")
    global activesession
    if not activesession:
        # Get a list of media files
        print("Contacting Server")
        posting = requests.post(f'{SERVER_URL}/api/hello',cookies=cookies,data="Hello")
        if posting.text != "hello":
            cookies['session_id'] = posting.text
            #CSUIT negotiation
            algorithms = ['AES', 'SEED', 'CAST5', 'TripleDES', 'Camellia']
            modes = ['GCM', 'CFB', 'CBC', 'CTR', 'OFB']
            dg = ['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
            code = 0
            for alg in algorithms:
                for mod in modes:
                    for dig in dg:
                        message = alg + '_' + mod + '_' + dig
                        posting = requests.post(f'{SERVER_URL}/api/csuit',data=message, cookies=cookies)
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
            #key negotiation
            # Generate a private key for use in the exchange.
            private_key = parameters.generate_private_key()

            public_key = private_key.public_key()
            pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo)
            posting = requests.post(f'{SERVER_URL}/api/difhell',data=pem, cookies=cookies)
            server_public_key = serialization.load_pem_public_key(
            posting.text.encode('latin'))

            shared_key = private_key.exchange(server_public_key)
            # Perform key derivation.
            derived_key = HKDF(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = None,
            info = b'handshake data').derive(shared_key)
            #KEY para o resto da sessao
            #derived_key
            # TODO: Secure the session
        activesession = True
    req = requests.get(f'{SERVER_URL}/api/list', cookies=cookies)
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
            posting = requests.post(f'{SERVER_URL}/api/bye',cookies=cookies,data="encripted bye message")
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
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}', cookies=cookies)
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