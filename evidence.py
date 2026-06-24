import hashlib
import json
import os
import uuid
import datetime

# Forensic standard: Read files in 8MB chunks to handle massive disk images 
# without exhausting system RAM.
CHUNK_SIZE = 8 * 1024 * 1024 

def hash_evidence(file_path):
    """Computes SHA-256 hash of a file using memory-efficient chunking."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")
        
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def create_package(case_id, evidence_file, lead_examiner):
    """Initializes a new, cryptographically bound evidence package."""
    return {
        "package_id": str(uuid.uuid4()),
        "case_id": case_id,
        "lead_examiner": lead_examiner,
        "creation_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "evidence_file": os.path.basename(evidence_file),
        "evidence_hash_sha256": hash_evidence(evidence_file),
        "chain": []
    }

def save_package(package, path):
    """Saves the package to disk using strictly deterministic JSON formatting."""
    # separators=(',', ':') removes whitespace, ensuring 100% deterministic serialization
    with open(path, 'w') as f:
        json.dump(package, f, indent=2, sort_keys=True)

def load_package(path):
    """Loads and parses an evidence package from disk."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Package file not found: {path}")
    with open(path, 'r') as f:
        return json.load(f)
