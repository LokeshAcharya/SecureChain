import os
import shutil
from config import CERTS_DIR
from ca import generate_root_ca, issue_certificate, revoke_certificate
from evidence import create_package, save_package, load_package
from examiner import verify_and_sign
from verify import verify_chain, generate_verification_report
from attack_sim import (
    attack_1_evidence_tampering, 
    attack_2_chain_injection, 
    attack_3_certificate_spoofing,
    attack_4_entry_deletion
)
from cryptography import x509

def setup_environment():
    """Cleans up previous runs to ensure a fresh state."""
    if os.path.exists(CERTS_DIR):
        shutil.rmtree(CERTS_DIR)
    for f in ["evidence.bin", "package_clean.json"]:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("="*60)
    print("INITIALIZING SECURE EVIDENCE CHAIN (REAL-WORLD STANDARD)")
    print("="*60)
    setup_environment()

    # 1. Setup CA and Examiners
    print("\n[1] Generating Root CA (RSA 3072, Encrypted Key)...")
    generate_root_ca()
    
    print("[2] Issuing Certificates to Examiners (RSA 2048, Strict KeyUsage)...")
    issue_certificate("Alice_Smith", "EX-001")
    issue_certificate("Bob_Jones", "EX-002")

    # 2. Create Evidence
    print("\n[3] Creating Evidence File (Simulated chunked hash)...")
    with open("evidence.bin", "wb") as f:
        f.write(b"CRITICAL MALWARE SAMPLE: DO NOT EXECUTE. HASH: 8F4C2...")
        
    print("[4] Creating Evidence Package...")
    package = create_package("CASE-2026-889", "evidence.bin", "Alice_Smith")

    # 3. Normal Chain of Custody
    print("\n[5] Examiner Alice processes evidence...")
    verify_and_sign("Alice_Smith", package, "Received evidence, created forensic disk image.")
    
    print("\n[6] Examiner Bob processes evidence...")
    verify_and_sign("Bob_Jones", package, "Analyzed disk image, extracted network logs.")

    # 4. Initial Verification
    print("\n[7] Running Initial Verification...")
    results = verify_chain(package)
    generate_verification_report(results)

    # Save clean package for attack simulations
    save_package(package, "package_clean.json")

    # ==========================================
    # ATTACK SIMULATIONS
    # ==========================================
    
    # Attack 1
    print("\n" + "="*60)
    print("SIMULATING ATTACK 1: EVIDENCE TAMPERING")
    print("="*60)
    pkg_atk1 = load_package("package_clean.json")
    attack_1_evidence_tampering(pkg_atk1)
    generate_verification_report(verify_chain(pkg_atk1))

    # Attack 2
    print("\n" + "="*60)
    print("SIMULATING ATTACK 2: CHAIN ENTRY INJECTION")
    print("="*60)
    pkg_atk2 = load_package("package_clean.json")
    attack_2_chain_injection(pkg_atk2)
    generate_verification_report(verify_chain(pkg_atk2))

    # Attack 3
    print("\n" + "="*60)
    print("SIMULATING ATTACK 3: CERTIFICATE SPOOFING")
    print("="*60)
    pkg_atk3 = load_package("package_clean.json")
    attack_3_certificate_spoofing(pkg_atk3)
    generate_verification_report(verify_chain(pkg_atk3))

    # Attack 4
    print("\n" + "="*60)
    print("SIMULATING ATTACK 4: ENTRY DELETION / REPLAY")
    print("="*60)
    pkg_atk4 = load_package("package_clean.json")
    attack_4_entry_deletion(pkg_atk4)
    generate_verification_report(verify_chain(pkg_atk4))

    # Bonus: Test Revocation
    print("\n" + "="*60)
    print("BONUS: TESTING CERTIFICATE REVOCATION (X.509 CRL)")
    print("="*60)
    with open("certs/examiners/Bob_Jones_cert.pem", "rb") as f:
        bob_cert = x509.load_pem_x509_certificate(f.read())
        
    print(f"Revoking Bob's certificate (Serial: {bob_cert.serial_number})...")
    revoke_certificate(bob_cert.serial_number)
    
    pkg_atk5 = load_package("package_clean.json")
    print("Verifying chain with revoked certificate...")
    generate_verification_report(verify_chain(pkg_atk5))

if __name__ == "__main__":
    main()
