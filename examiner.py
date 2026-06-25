import os
import json
import datetime
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from config import EXAMINERS_DIR, DEFAULT_EXAMINER_PASSWORD
from ca import verify_certificate

def load_examiner(examiner_name):
    """Loads the examiner's encrypted private key and certificate."""
    key_path = os.path.join(EXAMINERS_DIR, f"{examiner_name}_key.pem")
    cert_path = os.path.join(EXAMINERS_DIR, f"{examiner_name}_cert.pem")
    
    if not os.path.exists(key_path) or not os.path.exists(cert_path):
        raise FileNotFoundError(f"Credentials not found for examiner: {examiner_name}")

    # Decrypt the private key using the secure passphrase
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=DEFAULT_EXAMINER_PASSWORD)
        
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        
    # Proactively verify the examiner's own certificate before allowing them to work
    is_valid, msg = verify_certificate(cert)
    if not is_valid:
        raise PermissionError(f"Examiner {examiner_name} is not authorized to sign. Reason: {msg}")
        
    return key, cert

def _get_deterministic_payload(entry_dict):
    """
    Returns a strictly deterministic JSON byte string of the entry.
    Excludes the 'signature' field to prevent circular dependency during signing.
    """
    payload = {k: v for k, v in entry_dict.items() if k != "signature"}
    # sort_keys=True and specific separators guarantee identical byte-for-byte output
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

def _calculate_entry_hash(entry_dict):
    """Calculates the SHA-256 hash of a fully formed entry (including its signature)."""
    entry_bytes = json.dumps(entry_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(entry_bytes).hexdigest()

def sign_entry(examiner_name, package, action):
    """Creates and cryptographically signs a new chain entry."""
    key, cert = load_examiner(examiner_name)
    
    # 1. Determine Sequence Number (prevents reordering/deletion attacks)
    sequence_number = len(package["chain"])
    
    # 2. Determine Previous Hash (links the chain)
    if sequence_number == 0:
        previous_hash = package["evidence_hash_sha256"]
    else:
        previous_hash = _calculate_entry_hash(package["chain"][-1])

    # 3. Extract Examiner ID from Certificate
    try:
        examiner_id = cert.subject.get_attributes_for_oid(x509.oid.NameOID.USER_ID)[0].value
    except IndexError:
        examiner_id = "UNKNOWN"

    # 4. Build Entry Payload
    entry = {
        "sequence_number": sequence_number,
        "examiner_name": examiner_name,
        "examiner_id": examiner_id,
        "action": action,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "previous_hash": previous_hash,
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    }
    
    # 5. Sign the deterministic payload using RSA-PSS (Industry standard for signatures)
    payload_bytes = _get_deterministic_payload(entry)
    signature = key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    entry["signature"] = base64.b64encode(signature).decode('utf-8')
    return entry

def verify_and_sign(examiner_name, package, action):
    """
    REAL-WORLD STANDARD: Verifies the entire existing chain before appending a new entry.
    If the chain is broken, the examiner cryptographically refuses to sign.
    """
    # Importing here to avoid circular dependency issues with verify.py
    from verify import verify_chain 
    
    print(f"\n[{examiner_name}] Performing mandatory pre-signing chain verification...")
    verification = verify_chain(package)
    
    if not verification["is_valid"]:
        # CRITICAL: Refuse to sign a compromised chain
        raise ValueError(f"CHAIN INTEGRITY COMPROMISED. {examiner_name} refuses to sign. Reason: {verification['error']}")
    
    print(f"[{examiner_name}] Chain verified. Signing new entry (Sequence #{len(package['chain'])})...")
    entry = sign_entry(examiner_name, package, action)
    
    # Append to package
    package["chain"].append(entry)
    return entry
