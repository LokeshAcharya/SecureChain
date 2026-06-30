import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import (
    CertificateRevocationListBuilder, 
    RevokedCertificateBuilder,
    load_pem_x509_certificate,
    load_pem_x509_crl
)

from config import (
    CERTS_DIR, EXAMINERS_DIR, CRL_DIR,
    CA_KEY_PATH, CA_CERT_PATH, CRL_PATH,
    CA_KEY_SIZE, EXAMINER_KEY_SIZE,
    DEFAULT_CA_PASSWORD, DEFAULT_EXAMINER_PASSWORD
)

def setup_dirs():
    """Ensures all required directories exist."""
    os.makedirs(EXAMINERS_DIR, exist_ok=True)
    os.makedirs(CRL_DIR, exist_ok=True)

def generate_root_ca():
    """Generates the Root CA, encrypts the key at rest, and creates the initial CRL."""
    setup_dirs()
    
    # 1. Generate RSA 3072-bit key
    key = rsa.generate_private_key(public_exponent=65537, key_size=CA_KEY_SIZE)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Federal Forensics Bureau"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Root Evidence CA"),
    ])
    
    # 2. Build Certificate with strict extensions
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650) # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False, 
            data_encipherment=False, key_agreement=False, key_cert_sign=True, 
            crl_sign=True, encipher_only=False, decipher_only=False
        ), critical=True,
    ).sign(key, hashes.SHA256())

    # 3. Save Key (ENCRYPTED AT REST)
    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            # BestAvailableEncryption uses AES-256-CBC + PBKDF2
            encryption_algorithm=serialization.BestAvailableEncryption(DEFAULT_CA_PASSWORD) 
        ))
        
    # 4. Save Cert
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    # 5. Initialize empty CRL
    _generate_and_save_crl(key, cert, [])
        
    return key, cert

def _generate_and_save_crl(ca_key, ca_cert, revoked_serials):
    """Helper to build and save a cryptographically signed X.509 CRL."""
    builder = CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=1))

    for serial in revoked_serials:
        revoked_cert = RevokedCertificateBuilder().serial_number(
            serial
        ).revocation_date(
            datetime.datetime.utcnow()
        ).build()
        builder = builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL with the CA key
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open(CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

def load_ca():
    """Loads the CA key (decrypting it) and certificate."""
    with open(CA_KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=DEFAULT_CA_PASSWORD)
    with open(CA_CERT_PATH, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    return key, cert

def load_crl():
    """Loads the X.509 CRL."""
    with open(CRL_PATH, "rb") as f:
        return load_pem_x509_crl(f.read())

def issue_certificate(examiner_name, examiner_id):
    """Issues a strictly constrained certificate to an examiner."""
    ca_key, ca_cert = load_ca()
    
    # Generate Examiner Key
    ex_key = rsa.generate_private_key(public_exponent=65537, key_size=EXAMINER_KEY_SIZE)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Forensics Dept"),
        x509.NameAttribute(NameOID.COMMON_NAME, examiner_name),
        x509.NameAttribute(NameOID.USER_ID, examiner_id),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        ex_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        # Strictly limit examiner certs to digital signatures only
        x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False, 
            data_encipherment=False, key_agreement=False, key_cert_sign=False, 
            crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True,
    ).sign(ca_key, hashes.SHA256())

    # Save Examiner Key (ENCRYPTED) and Cert
    key_path = os.path.join(EXAMINERS_DIR, f"{examiner_name}_key.pem")
    cert_path = os.path.join(EXAMINERS_DIR, f"{examiner_name}_cert.pem")
    
    with open(key_path, "wb") as f:
        f.write(ex_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(DEFAULT_EXAMINER_PASSWORD)
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    return ex_key, cert

def revoke_certificate(serial_number):
    """Revokes a certificate by updating and re-signing the X.509 CRL."""
    ca_key, ca_cert = load_ca()
    crl = load_crl()
    
    # Extract existing revoked serials
    revoked_serials = [rev.serial_number for rev in crl]
    
    # Add new serial if not already present
    if serial_number not in revoked_serials:
        revoked_serials.append(serial_number)
        
    # Rebuild and save the signed CRL
    _generate_and_save_crl(ca_key, ca_cert, revoked_serials)
    print(f"[CA] Certificate {serial_number} revoked and CRL updated.")

def verify_certificate(cert):
    """Comprehensive verification of an examiner certificate."""
    _, ca_cert = load_ca()
    
    # 1. Verify CA signature on the certificate
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False, "Invalid CA signature on certificate."

    # 2. Check Validity Dates
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False, "Certificate is expired or not yet valid."

    # 3. Verify CRL integrity and check revocation status
    crl = load_crl()
    if not crl.is_signature_valid(ca_cert.public_key()):
        return False, "CRL signature is invalid (CRL may be tampered)."
        
    revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked_cert:
        return False, f"Certificate is revoked."

    # 4. Check Key Usage (Ensure it's allowed to sign data)
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not key_usage.value.digital_signature:
            return False, "Certificate lacks digitalSignature key usage."
    except x509.ExtensionNotFound:
        return False, "Certificate missing Key Usage extension."

    return True, "Valid"
