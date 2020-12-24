#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

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
modos = ['GCM', 'CFB', 'CBC', 'CTR', 'OFB']
dg =['SHA256', 'SHA512', 'SHA3256', 'SHA3512']
users = []
CSUIT = {}
digests = {}
ciphers = {}
# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=512)

def start_cifra(key,iv,who):
    global digests
    global CSUIT
    alg,modo,dige = CSUIT[who].split("_")
    if(dige == "SHA256"):
        digests[who] = hashes.Hash(hashes.SHA256())
    elif(dige == "SHA512"):
        digests[who] = hashes.Hash(hashes.SHA512())
    elif(dige == "SHA3256"):
        digests[who] = hashes.Hash(hashes.SHA3_256())
    elif(dige == "SHA3512"):
        digests[who] = hashes.Hash(hashes.SHA3_512())
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
    cifra = Cipher(algorithm,mode)
    return cifra

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
            elif request.path == b'/api/difhell':
                # key negotiation
                # Generate a private key for use in the exchange.
                private_key = parameters.generate_private_key()
                public_key = private_key.public_key()
                peer_public_key = serialization.load_pem_public_key(
                    request.content.getvalue())
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
                iv3 = os.urandom(16)
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
                cf1 = start_cifra(key1,iv1,who)
                cf2 = start_cifra(key2,iv2,who)
                cf3 = start_cifra(key3,iv3,who)
                ciphers[who] = [cf1,cf2,cf3]
                return json.dumps({'pem':pem.decode('latin'),'ivs':[iv1.decode('latin'),iv2.decode('latin'),iv3.decode('latin')]}, indent=4).encode('latin')
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