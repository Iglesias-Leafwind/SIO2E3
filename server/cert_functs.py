from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os
from datetime import datetime

def get_issuers(certificate, cert_dic, chain=[]):
    chain.append(certificate)

    issuer = certificate.issuer.rfc4514_string()
    subject = certificate.subject.rfc4514_string()

    if issuer == subject and subject in cert_dic:
        return chain
    
    if issuer in cert_dic:
        return get_issuers(cert_dic[issuer], chain)

    print("Unable to create the Trust Chain")
    return False
