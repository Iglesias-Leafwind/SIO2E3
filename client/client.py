#TODO LIST CLIENT
"""
    done?31-Unique users id created from server
    done?2-Verification if already logged in (with flag)
    done?3-Bye server message
    done?4-Arranjar global variables???
    done?5-Mudar length da derivacao da key para criar 3 keys ao mesmo tempo 1 para criptar data outra para hmac e outra para mensagem
    done?6-Set a todas mensagens para estarem criptadas com um hmac (a mensagem enviada com estes 2 tambem estara encriptada com uma 3 key)
    done?7-Set a todos chunks com derivação das keys pela principal e por algo no ficheiro?
8-Escrever o protocolo de como isto tudo foi feito para o relatorio
"""
# TODO SERVER
"""
    done?1-Gerar um id para cada cliente
    done?2-Aceitar um hello e criar o cliente caso ele n esteja ja ligado se estiver n faz nada ou envia um hello de resposta para dizer que o user ja esta com uma sessao
    done?3-Quando receber bye message eleminar cliente
    done?4-Gerar ivs e mandar ao cliente 
    done?5-Criar dicionarios para guardar toda informação necessaria
    done?6-No dicionario das keys vai estar por ordem (keyCifrarTudo,keyCifrarData,keyCifrarMac)
    done?7-Arranjar global variables???
    done?8-Set a todas mensagens para estarem criptadas de acordo com o uuid da pessoa e as suas keys
    doing?9-Derivaçao das chaves por chunk pelas keys e por algo no ficheiro
10-Escrever o protocolo de isto tudo para o relatorio
    done?NOTA a maneira como guardamos no cliente e no server as chaves usadas para cifrar vai ser diferente
"""
#TODO NOTAS
"""
    done?Fazer verificação de quanto é que um user ja viu
    done?Encrypt then mac aka mac da cifra
Licenca por musica que o user so precisa de mostrar por leitura da musica depois de receber a licenca
Se a licenca acabar o user precisa pedir outra licenca / pede automaticamente
User vai mandar o seu CC como identificador de log in e o server envia um uuid para ele distinguir os users
    done?Sintese chunk pelo id do chunk?

"""
import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509, exceptions
from cryptography.x509.oid import NameOID
from datetime import datetime
from cert_functs import *
import PyKCS11
import binascii


#cookies usadas para determinar o id deste cliente
cookies = {'session_id': 'noID'}
#CSUIT usado na comunicação entre o server-cliente
CSUIT = ""
#Onde as cifras estarão guardadas
cifras = []
dKey = b""
#Parametros para a geração de chaves que pode ser reutilizado
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
params_numbers = dh.DHParameterNumbers(p,g)
parameters = params_numbers.parameters(default_backend())

#logs
logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
#Server URl
SERVER_URL = 'http://127.0.0.1:8080'
trusted_certs = {}

client_cert = ""
with open("client.crt", "rb") as file:
    certificate_data = file.read()
    client_cert = x509.load_pem_x509_certificate(certificate_data, backend=default_backend())

crl = ""
with open("GTS1O1core.crl", "rb") as file:
    crl_data = file.read()
    print(type(crl_data))
    crl = x509.load_pem_x509_crl(crl_data)

all_files = os.scandir("/etc/ssl/certs")
for f in all_files:
    if not f.is_dir():
        try:
            cert = ""
            with open(f, "rb") as file:
                cert_data = file.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            if datetime.now().timestamp() > cert.not_valid_before.timestamp() or datetime.now().timestamp() < cert.not_valid_after.timestamp():
                trusted_certs[cert.subject.rfc4514_string()] = cert

        except Exception as e:
            print("Error: ", e, "\n")

#função usada para inicializar o HMAC dependendo do modo de comunicação
def start_hmac(key):
    global CSUIT
    alg,modo,dige = CSUIT.split("_")
    if(dige == "SHA256"):
        digest = hashes.SHA256()
    elif(dige == "SHA512"):
        digest = hashes.SHA512()
    elif(dige == "SHA3256"):
        digest = hashes.SHA3_256()
    elif(dige == "SHA3512"):
        digest = hashes.SHA3_512()
    return hmac.HMAC(key, digest, backend=default_backend())
#função usada para inicializar as cifras dependendo do modo de comunicação
def start_cifra(key,iv):
    global CSUIT
    alg,modo,dige = CSUIT.split("_")
    if(modo == 'CFB'):
        mode = modes.CFB(iv)
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
    cifra = Cipher(algorithm,mode)
    return cifra
#função usada para cifrar data para ser enviada ao server de acordo com as 2 cifras guardadas e o hmac
def cifrar(data):
    global cifras
    criptar = cifras[1].encryptor()
    cifrado = criptar.update(data.encode('latin')) + criptar.finalize()
    criptar = cifras[2].copy()
    criptar.update(cifrado)
    MAC = criptar.finalize()
    dict = {'data':cifrado.decode('latin'),'HMAC':MAC.decode('latin')}
    criptar = cifras[0].encryptor()
    return criptar.update(json.dumps(dict, indent=4).encode('latin')) + criptar.finalize()
#função usada para decifrar data recebida do server de acordo com as 2 cifras guardadas e o hmac
def decifrar(data):
    global cifras
    decriptar = cifras[0].decryptor()
    decifrado = decriptar.update(data) + decriptar.finalize()
    decifrado = json.loads(decifrado.decode('latin'))
    decriptar = cifras[2].copy()
    decriptar.update(decifrado['data'].encode('latin'))
    MAClinha = decriptar.finalize()
    if(MAClinha != decifrado['HMAC'].encode('latin')):
        return "ERROR 500"

    decriptar = cifras[1].decryptor()
    decifrado = decriptar.update(decifrado['data'].encode('latin')) + decriptar.finalize()
    return decifrado.decode('latin')

def verify_signature(issuer, client_cert):
    global server_cert
    try:
        issuer.public_key().verify(client_cert.signature, client_cert.tbs_certificate_bytes, padding.PKCS1v15(), client_cert.signature_hash_algorithm,)
        return True
    except exceptions.InvalidSignature:
        return False

def verify_dates(client_cert):
    if datetime.now().timestamp() > cert.not_valid_after.timestamp() or datetime.now().timestamp() < cert.not_valid_before.timestamp():
        print("Expired Certificate")
        return False
    print("Valid Certificate")
    return True

#activesession é usado para ver se ja temos alguma sessao ja aberta ou nao
activesession = False
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")
    global activesession
    global cifras
    global CSUIT
    global dKey
    global client_cert
    #se ainda n existir uma activesession
    #TODO authentication using CC checking if I am allowed or not and getting server certificates and etc

    if not activesession:
        # Get a list of media files
        print("Contacting Server")

        server_cert = requests.get(f'{SERVER_URL}/api/certs', cookies=cookies)
        server_cert = x509.load_pem_x509_certificate(server_cert.content, backend=default_backend())

        isVerified = True

        chain = get_issuers(client_cert, trusted_certs, [])
        if chain:
            for cert in chain:
                if not (verify_signature(trusted_certs[cert.issuer.rfc4514_string()], cert) and verify_dates(cert)):
                    isVerified = False
        else:
            isVerified = False

        if not isVerified:
            return "ERROR 505"

        #dizemos hello ao server
        posting = requests.post(f'{SERVER_URL}/api/hello',cookies=cookies,data=client_cert.public_bytes(encoding = serialization.Encoding.PEM))
        #se o que recebermos não é hello quer dizer que nao existe uma sessao aberta
        #TODO aqui autenticamos pelo cc e fechamos a sessao aberta se o cc for o correto
        #TODO E abrimos uma nova sessao
        if posting.text != "hello":
            #recebemos a id da nossa sessao e guardamos como um cookie que queremos enviar nas seguintes comunicações
            cookies['session_id'] = posting.text
            print(posting.text)
            #CSUIT negotiation
            #TODO randomizar o csuit? amybe not cause we need to import random
            #TODO testar todos CSUIT (YES TODAS COMBINAções)
            algorithms = ['AES', 'SEED', 'CAST5', 'TripleDES', 'Camellia']
            modes = ['CFB', 'CTR', 'OFB']
            dg = ['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
            code = 0
            for alg in algorithms:
                for mod in modes:
                    for dig in dg:
                        message = alg + '_' + mod + '_' + dig
                        #perguntamos se o server tem esta combinação de CSUIT
                        posting = requests.post(f'{SERVER_URL}/api/csuit',data=message, cookies=cookies)
                        code = posting.status_code
                        #se sim entao determinamos este como o nosso csuit e seguimos em frente
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
            # Generate a public key
            public_key = private_key.public_key()
            # transform that public key into a readable and sendable object
            pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo)
            # send public key to the server and receive server public key / all ivs needed for the ciphers
            posting = requests.post(f'{SERVER_URL}/api/difhell',data=pem, cookies=cookies)
            info = posting.json()
            #get ivs
            ivs = info['ivs']
            #get server public key
            server_public_key = serialization.load_pem_public_key(
            info['pem'].encode('latin'))
            # exchange using our private key and the server's public key
            shared_key = private_key.exchange(server_public_key)
            # Perform key derivation.
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=96,
                salt=None,
                info=b'handshake data').derive(shared_key)
            # and divide the key into 3 keys with length 32 meaning it will be a 256 length key that can be used as a key
            # for the ciphers
            key1 = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(derived_key[0:31])
            key2 = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(derived_key[32:63])
            key3 = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(derived_key[64:95])
            dKey = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(key1 + key2 + key3)
            # create and save ciphers + hmac
            cifras += [start_cifra(key1,ivs[0].encode('latin'))]
            cifras += [start_cifra(key2,ivs[1].encode('latin'))]
            cifras += [start_hmac(key3)]
        # set activesession as True cause there is a active session up and running
        activesession = True
    #this is for testing comunication ignore these lines
    #posting = requests.post(f'{SERVER_URL}/api/ok', data=cifrar("Testing Hello"), cookies=cookies)
    #print(decifrar(posting.content))

    #get music list now that we have permission
    req = requests.get(f'{SERVER_URL}/api/list', cookies=cookies)
    if req.status_code == 200:
        print("Got Server List")

    media_list = json.loads(decifrar(req.content))


    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            # we can only leave this session with this user when the server receives this encripted message
            # in case someone steals your id and tries to stop you from staying logged in then he needs to know your keys
            # and CSUIT to stop you
            posting = requests.post(f'{SERVER_URL}/api/bye',cookies=cookies,data=cifrar("encripted bye message"))
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
        #decifrar com rotação de chaves
        #using dkey para derivar
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}', cookies=cookies)
        criptedData = json.loads(decifrar(req.content))
        if("error" in criptedData.keys()):
            break
        mainDataCipher = start_cifra(dKey,criptedData['iv'].encode('latin')).decryptor()
        dKey = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'handshake data').derive(dKey + cifrar(criptedData['data']))

        decriptar = start_hmac(dKey).copy()
        decriptar.update(criptedData['data'].encode('latin'))
        MAClinha = decriptar.finalize()
        if (MAClinha != criptedData['HMAC'].encode('latin')):
            return "ERROR 500"

        decifrado = mainDataCipher.update(criptedData['data'].encode('latin')) + mainDataCipher.finalize()
        chunk = json.loads(decifrado.decode('latin'))

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