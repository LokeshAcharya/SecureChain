import os
import json
import datetime
import hashlib
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def attack_1_evidence_tampering(package):
    """Modifies the evidence hash after signing."""
    print("\n[ATTACK 1] Tampering with Evidence Hash...")
    package["evidence_hash_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
    print("[ATTACK 1] Evidence hash replaced with fake hash.")

def attack_2_chain_injection(package):
    """Injects a fake examiner entry mid-chain."""
    print("\n[ATTACK 2] Injecting Fake Chain Entry...")
    fake_entry = {
        "sequence_number": 1,
        "examiner_name": "Fake Inspector",
        "examiner_id": "9999",
        "action": "Evidence modified to remove malware traces",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "previous_hash": package["chain"][0]["previous_hash"], 
        "certificate_pem": package["chain"][0]["certificate_pem"], 
        "signature": base64.b64encode(b"fake_signature_bytes").decode('utf-8')
    }
    package["chain"].insert(1, fake_entry)
    # Attacker tries to fix sequence numbers for subsequent entries
    for i in range(2, len(package["chain"])):
        package["chain"][i]["sequence_number"] = i
    print("[ATTACK 2] Fake entry injected at index 1.")

def attack_3_certificate_spoofing(package):
    """Signs with a rogue certificate not issued by the CA."""
    print("\n[ATTACK 3] Spoofing Certificate (Rogue CA)...")
    
    # Generate rogue key and self-signed cert
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Rogue CA"),
    ])
    rogue_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        rogue_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(rogue_key, hashes.SHA256())

    prev_entry_str = json.dumps(package["chain"][-1], sort_keys=True, separators=(',', ':')).encode('utf-8')
    previous_hash = hashlib.sha256(prev_entry_str).hexdigest()

    rogue_entry = {
        "sequence_number": len(package["chain"]),
        "examiner_name": "Rogue Actor",
        "examiner_id": "6666",
        "action": "Planting false evidence",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "previous_hash": previous_hash,
        "certificate_pem": rogue_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    }
    
    # Sign with rogue key
    payload = {k: v for k, v in rogue_entry.items() if k != "signature"}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = rogue_key.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    rogue_entry["signature"] = base64.b64encode(signature).decode('utf-8')
    
    package["chain"].append(rogue_entry)
    print("[ATTACK 3] Rogue entry appended with self-signed certificate.")

def attack_4_entry_deletion(package):
    """Deletes an entry and attempts to fix the chain."""
    print("\n[ATTACK 4] Deleting a Chain Entry (Replay/Deletion Attack)...")
    if len(package["chain"]) > 1:
        deleted_entry = package["chain"].pop(1)
        print(f"[ATTACK 4] Deleted entry for '{deleted_entry['examiner_name']}'.")
        # Attacker tries to fix the sequence numbers
        for i in range(1, len(package["chain"])):
            package["chain"][i]["sequence_number"] = i
        print("[ATTACK 4] Attacker attempted to re-index sequence numbers.")
