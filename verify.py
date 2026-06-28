import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from ca import verify_certificate

def _get_deterministic_payload(entry_dict):
    """Reconstructs the exact byte payload that was signed."""
    payload = {k: v for k, v in entry_dict.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

def _calculate_entry_hash(entry_dict):
    """Calculates the SHA-256 hash of a fully formed entry (including signature)."""
    entry_bytes = json.dumps(entry_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(entry_bytes).hexdigest()

def verify_entry(entry, expected_sequence, expected_previous_hash):
    """Deep verification of a single chain entry."""
    # 1. Check Sequence Number (Prevents deletion/reordering)
    if entry.get("sequence_number") != expected_sequence:
        return False, f"Sequence number mismatch. Expected {expected_sequence}, got {entry.get('sequence_number')}"

    # 2. Check Chain Linkage (Prevents tampering with previous entries)
    if entry.get("previous_hash") != expected_previous_hash:
        return False, "Chain broken: previous_hash mismatch."

    # 3. Load and Verify Certificate (Checks CA signature, dates, and CRL)
    try:
        cert = x509.load_pem_x509_certificate(entry["certificate_pem"].encode('utf-8'))
    except Exception as e:
        return False, f"Failed to load certificate: {e}"

    is_valid_cert, cert_msg = verify_certificate(cert)
    if not is_valid_cert:
        return False, f"Certificate invalid: {cert_msg}"

    # 4. Verify Digital Signature (RSA-PSS)
    payload_bytes = _get_deterministic_payload(entry)
    try:
        signature = base64.b64decode(entry["signature"])
    except Exception:
        return False, "Invalid signature encoding."

    try:
        cert.public_key().verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False, "Invalid digital signature (payload tampered or wrong key)."

    return True, "Valid"

def verify_chain(package):
    """Verifies the complete evidence package from scratch."""
    results = {
        "is_valid": True,
        "error": None,
        "entries": []
    }

    # The first entry must link to the original evidence hash
    expected_prev_hash = package["evidence_hash_sha256"]

    for i, entry in enumerate(package["chain"]):
        is_valid, msg = verify_entry(entry, expected_sequence=i, expected_previous_hash=expected_prev_hash)
        
        results["entries"].append({
            "index": i,
            "examiner": entry.get("examiner_name", "Unknown"),
            "action": entry.get("action", "Unknown"),
            "valid": is_valid,
            "message": msg
        })

        if not is_valid:
            results["is_valid"] = False
            results["error"] = f"Entry {i} failed: {msg}"
            break # Stop at first failure to prevent cascading errors

        # Update expected hash for the next entry
        expected_prev_hash = _calculate_entry_hash(entry)

    return results

def generate_verification_report(results):
    """Prints a clear, forensic-grade verification report."""
    print("\n" + "="*60)
    print("EVIDENCE CHAIN VERIFICATION REPORT")
    print("="*60)
    if results["is_valid"]:
        print("STATUS: ✅ PASS - Chain is fully intact and cryptographically valid.")
    else:
        print(f"STATUS: ❌ FAIL - {results['error']}")
        
    print("\nDetailed Entry Checks:")
    if not results["entries"]:
        print("  (No entries in chain)")
    for entry in results["entries"]:
        status = "✅" if entry["valid"] else "❌"
        print(f"  [{status}] Seq #{entry['index']} ({entry['examiner']}): {entry['message']}")
    print("="*60 + "\n")
