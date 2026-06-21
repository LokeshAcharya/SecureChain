import os
from cryptography.hazmat.primitives import hashes

# 1. DIRECTORY & FILE PATHS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
EXAMINERS_DIR = os.path.join(CERTS_DIR, "examiners")
CRL_DIR = os.path.join(CERTS_DIR, "crl")

CA_KEY_PATH = os.path.join(CERTS_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca_cert.pem")
CRL_PATH = os.path.join(CRL_DIR, "ca_crl.pem")

# 2. CRYPTOGRAPHIC PARAMETERS (NIST Standards)
CA_KEY_SIZE = 3072 
EXAMINER_KEY_SIZE = 2048 
HASH_ALGORITHM = hashes.SHA256()

# 3. CREDENTIALS (DEMO ONLY)
DEFAULT_CA_PASSWORD = b"UltraSecure_RootCA_Passphrase_2026!"
DEFAULT_EXAMINER_PASSWORD = b"Examiner_Secure_Pass_2026!"
