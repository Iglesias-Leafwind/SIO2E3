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

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

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

algort = ['AES', 'SEED', 'CAST5', 'TripleDES', 'Camellia']
modos = ['CFB', 'CBC', 'CTR', 'OFB']
dg =['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
users = []
CSUIT = {}
ciphers = {}
# Generate some parameters. These can be reused.
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

params_numbers = dh.DHParameterNumbers(p,g)
parameters = params_numbers.parameters(default_backend())

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

def start_cifra(key,iv,who):
    global CSUIT
    alg,modo,dige = CSUIT[who].split("_")
    if(modo == 'CFB'):
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
    cifra = Cipher(algorithm,mode)
    return cifra

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
    def do_list(self, request):

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
        return json.dumps(media_list, indent=4).encode('latin')

    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
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
            return json.dumps({'error': 'invalid chunk id','data': 'brak'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        who = request.received_cookies["session_id".encode('latin')].decode('latin')
        logger.debug(f'{who} : Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

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
                    length=32,
                    salt=None,
                    info=b'handshake data').derive(derived_key[0:31])
                key2 = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data').derive(derived_key[32:63])
                key3 = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data').derive(derived_key[64:95])
                iv1 = os.urandom(16)
                iv2 = os.urandom(16)
                cf1 = start_cifra(key1,iv1,who)
                cf2 = start_cifra(key2,iv2,who)
                cf3 = start_hmac(key3,who)
                ciphers[who] = [cf1,cf2,cf3]
                return json.dumps({'pem':pem.decode('latin'),'ivs':[iv1.decode('latin'),iv2.decode('latin')]}, indent=4).encode('latin')
            elif request.path == b'/api/bye':
                if request.content.getvalue() == b"encripted bye message":
                    users.remove(who)
                    return b"bye"
                return b"No"
            elif request.path == b'/api/hello':
                if(who in users):
                    return b"hello"
                who = os.urandom(16)
                while(who.decode('latin') in users):
                    who = os.urandom(16)
                users += [who.decode('latin')]
                return who
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