#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from datetime import datetime
from cert_functs import *

#logs
logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

#music catalog
CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce':
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

#available csuit configs
algort = ['AES', 'SEED', 'CAST5', 'TripleDES', 'Camellia']
modos = ['CFB', 'CTR', 'OFB']
dg =['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
#this is where we keep all user ids
#TODO turn this into a dict with cc and id verification? or just use CC as ID?
users = []
#this is where we keep CSUIT of each user through their id
CSUIT = {}
#this is where we keep a list of ciphers used in the comunication through user id
ciphers = {}
dKey = {}
readings = {}
# Generate some parameters. These can be reused.
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
params_numbers = dh.DHParameterNumbers(p,g)
parameters = params_numbers.parameters(default_backend())

trusted_certs = {}

server_cert = ""
with open("localhost.crt", "rb") as file:
    certificate_data = file.read()
    server_cert = x509.load_pem_x509_certificate(certificate_data, backend=default_backend())

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

#function used to initialize hmac based on key and user id
def start_hmac(key,who):
    global CSUIT
    alg,modo,dige = CSUIT[who].split("_")
    if(dige == "SHA256"):
        digest = hashes.SHA256()
    elif(dige == "SHA512"):
        digest = hashes.SHA512()
    elif(dige == "SHA3256"):
        digest = hashes.SHA3_256()
    elif(dige == "SHA3512"):
        digest = hashes.SHA3_512()
    return hmac.HMAC(key, digest, backend=default_backend())

#function used to initialize cipher based on a key an iv and user id
def start_cifra(key,iv,who):
    global CSUIT
    alg,modo,dige = CSUIT[who].split("_")
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

#function used to encrypt data based on user id
def cifrar(data,who):
    global ciphers
    cifras = ciphers[who]
    criptar = cifras[1].encryptor()
    cifrado = criptar.update(data.encode('latin')) + criptar.finalize()
    criptar = cifras[2].copy()
    criptar.update(cifrado)
    MAC = criptar.finalize()
    dict = {'data':cifrado.decode('latin'),'HMAC':MAC.decode('latin')}
    criptar = cifras[0].encryptor()
    return criptar.update(json.dumps(dict, indent=4).encode('latin')) + criptar.finalize()

#function used to decrypt data based on user id
def decifrar(data,who):
    global ciphers
    cifras = ciphers[who]
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

class MediaServer(resource.Resource):
    isLeaf = True

    # Send the list of media files to clients
    def do_list(self, request,who):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return cifrar(json.dumps(media_list, indent=4),who)

    # Send a media chunk to the client
    def do_download(self, request,who):
        global dKey
        global readings
        global CSUIT
        logger.debug(f'Download: args: {request.args}')

        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return cifrar(json.dumps({'error': 'invalid media id'}),who)

        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return cifrar(json.dumps({'error': 'media file not found'}),who)

        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return cifrar(json.dumps({'error': 'invalid chunk id','data': 'brak'}),who)
        if(who not in readings.keys()):
            readings[who] = {media_id:0}
        elif(media_id not in readings[who].keys()):
            readings[who][media_id] = 0

        logger.debug(f'Download: chunk: {chunk_id} - readingsByChunk: {math.ceil((readings[who][media_id]*100) / media_item["file_size"])/100} ')

        offset = chunk_id * CHUNK_SIZE

        #TODO verificaçao de licensa?
        readings[who][media_id] += CHUNK_SIZE
        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            # cifrar com rotação de chaves
            # using dkey para derivar
            alg,modo,dige = CSUIT[who].split("_")
            blocksize = 16*8
            if(alg == 'AES'):
                blocksize = algorithms.AES.block_size
            elif(alg == 'SEED'):
                blocksize = algorithms.SEED.block_size
            elif(alg == 'CAST5'):
                blocksize = algorithms.CAST5.block_size
            elif(alg == 'TripleDES'):
                blocksize = algorithms.TripleDES.block_size
            elif(alg == 'Camellia'):
                blocksize = algorithms.Camellia.block_size
            newIv = os.urandom(int(blocksize/8))
            criptar = start_cifra(dKey[who],newIv,who).encryptor()
            cifradoData = criptar.update(json.dumps(
                    {
                        'media_id': media_id,
                        'chunk': chunk_id,
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')) + criptar.finalize()
            dKey[who] = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data').derive(dKey[who] + cifrar(cifradoData.decode('latin'),who))
            hmacing = start_hmac(dKey[who],who).copy()
            hmacing.update(cifradoData)
            cifradoHMAC = hmacing.finalize()
            dict = {'data': cifradoData.decode('latin'), 'HMAC': cifradoHMAC.decode('latin'), 'iv':newIv.decode('latin')}
            return cifrar(json.dumps(dict, indent=4),who)

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return cifrar(json.dumps({'error': 'unknown'}, indent=4),who)

    def verify_signature(self, client_cert):
        global server_cert
        try:
            server_cert.public_key().verify(client_cert.signature, client_cert.tbs_certificate_bytes,)
            return True
        except InvalidSignature:
            return False

    def verify_dates(self, client_cert):
        if datetime.now() > cert.not_valid_after or datetime.now() < cert.not_valid_before:
            print("Expired Certificate")
            return False
        print("Valid Certificate")
        return True
    
    def verify_extensions(seld, client_cert):
        try:
            values = client_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).values
        except ExtensionNotFoundException:
            print("Invalid certificate")
            return False
        return True

    # Handle a GET request
    def render_GET(self, request):
        global cert
        who = request.received_cookies["session_id".encode('latin')].decode('latin')
        logger.debug(f'{who} : Received request for {request.uri}')

        try:
            if request.path == b'/api/list':
                return self.do_list(request,who)

            elif request.path == b'/api/download':
                return self.do_download(request,who)
            elif request.path == b'/api/certs':
                return server_cert.public_bytes(encoding=serialization.Encoding.PEM)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/list /api/download' 
            
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    # Handle a POST request
    def render_POST(self, request):
        global users
        global CSUIT
        global keys
        global ciphers
        global digests
        global dkey
        who = request.received_cookies["session_id".encode('latin')].decode('latin')
        logger.debug(f'{who} : Received POST for {request.uri}')
        try:
            if request.path == b'/api/csuit':
                vars = (request.content.getvalue().decode('latin')).split("_")
                if vars[0] in algort and vars[1] in modos and vars[2] in dg:
                    request.setResponseCode(200)
                    CSUIT[who] = request.content.getvalue().decode('latin')
                    return b''
                else:
                    request.setResponseCode(201)
                    return b''
            elif request.path == b'/api/ok':
                logger.debug(f'{who} : Received {decifrar(request.content.getvalue(),who)}')
                return cifrar("NO",who)
            elif request.path == b'/api/difhell':
                # key negotiation
                # Generate a private key for use in the exchange.
                private_key = parameters.generate_private_key()
                public_key = private_key.public_key()
                peer_public_key = serialization.load_pem_public_key(
                    request.content.getvalue())
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
                #with correct public key and correct private key echange doesn't work
                shared_key = private_key.exchange(peer_public_key)
                # Perform key derivation.
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=96,
                    salt=None,
                    info=b'handshake data').derive(shared_key)
                # KEY para o resto da sessao
                # derived_key
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
                dKey[who] = HKDF(
                    algorithm=hashes.SHA256(),
                    length=16,
                    salt=None,
                    info=b'handshake data').derive(key1+key2+key3)

                alg, modo, dige = CSUIT[who].split("_")
                blocksize = 16*8
                if (alg == 'AES'):
                    blocksize = algorithms.AES.block_size
                elif (alg == 'SEED'):
                    blocksize = algorithms.SEED.block_size
                elif (alg == 'CAST5'):
                    blocksize = algorithms.CAST5.block_size
                elif (alg == 'TripleDES'):
                    blocksize = algorithms.TripleDES.block_size
                elif (alg == 'Camellia'):
                    blocksize = algorithms.Camellia.block_size
                iv1 = os.urandom(int(blocksize/8))
                iv2 = os.urandom(int(blocksize/8))
                cf1 = start_cifra(key1,iv1,who)
                cf2 = start_cifra(key2,iv2,who)
                cf3 = start_hmac(key3,who)
                ciphers[who] = [cf1,cf2,cf3]
                return json.dumps({'pem':pem.decode('latin'),'ivs':[iv1.decode('latin'),iv2.decode('latin')]}, indent=4).encode('latin')
            elif request.path == b'/api/bye':
                #TODO check CC to say bye
                if decifrar(request.content.getvalue(),who) == "encripted bye message":
                    users.remove(who)
                    return b"bye"
                return b"No"
            elif request.path == b'/api/hello':
                #TODO check CC and send user id if cc is correct
                if(who in users):
                    return b"hello"
                bcert = request.content.getvalue()
                client_cert = x509.load_pem_x509_certificate(bcert, backend=default_backend())
                isVerified = False
                for cert in trusted_certs.values():
                    if get_issuers(cert, trusted_certs, []):
                        isVerified = True
                
                if isVerified:
                    who = os.urandom(16)
                    while(who.decode('latin') in users):
                        who = os.urandom(16)
                    users += [who.decode('latin')]
                    return who
                else:
                    print(goodbye)
                    return b"goobye"
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/csuit /api/hello /api/bye /api/difhell'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()