import os
import sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature

# Configuration paths as per your project structure
PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"
CERTIFICATE_PATH = "certification/certificate.pem"
DOCUMENT_PATH = "documents/sample.txt"
SIGNATURE_PATH = "signature/sample.sig"

def ensure_directories():
    """Ensures that the required project directory structure exists."""
    for folder in ["keys", "certification", "documents", "signature"]:
        os.makedirs(folder, exist_ok=True)

def load_file(file_path):
    """Utility to read binary data from a file."""
    if not os.path.exists(file_path):
        print(f"[-] Error: File not found at {file_path}")
        return None
    with open(file_path, "rb") as f:
        return f.read()

def write_file(file_path, data):
    """Utility to write binary data to a file."""
    try:
        with open(file_path, "wb") as f:
            f.write(data)
        print(f"[+] Success: Data written to {file_path}")
        return True
    except Exception as e:
        print(f"[-] Error saving file: {e}")
        return False

def sign_document():
    """Signs the document using the private key and saves the signature."""
    print("\n--- Sign Document ---")
    
    # 1. Load the document
    doc_data = load_file(DOCUMENT_PATH)
    if doc_data is None:
        print("Please ensure your document exists at: " + DOCUMENT_PATH)
        return

    # 2. Load the private key
    key_bytes = load_file(PRIVATE_KEY_PATH)
    if key_bytes is None:
        return
    
    try:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None  # Assumes unencrypted key; provide password bytes if encrypted
        )
    except Exception as e:
        print(f"[-] Failed to parse private key: {e}")
        return

    # 3. Generate the signature
    try:
        signature = private_key.sign(
            doc_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # 4. Save the signature
        write_file(SIGNATURE_PATH, signature)
        print("[+] Document signed successfully!")
    except Exception as e:
        print(f"[-] Signing failed: {e}")

def verify_signature():
    """Verifies the document signature using the public key."""
    print("\n--- Verify Signature ---")
    
    doc_data = load_file(DOCUMENT_PATH)
    signature_data = load_file(SIGNATURE_PATH)
    key_bytes = load_file(PUBLIC_KEY_PATH)

    if not (doc_data and signature_data and key_bytes):
        print("[-] Verification halted due to missing files.")
        return

    try:
        public_key = serialization.load_pem_public_key(key_bytes)
    except Exception as e:
        print(f"[-] Failed to parse public key: {e}")
        return

    try:
        public_key.verify(
            signature_data,
            doc_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[+] SUCCESS: The digital signature is VALID. The document integrity is intact.")
    except InvalidSignature:
        print("[-] WARNING: The signature is INVALID! The document may have been tampered with.")
    except Exception as e:
        print(f"[-] Verification failed: {e}")

def verify_certificate():
    """Verifies the cryptographic validity and expiration dates of the certificate."""
    print("\n--- Verify Certificate Validity ---")
    
    cert_bytes = load_file(CERTIFICATE_PATH)
    if cert_bytes is None:
        return

    try:
        certificate = load_pem_x509_certificate(cert_bytes)
    except Exception as e:
        print(f"[-] Failed to parse X.509 certificate: {e}")
        return

    # Extract timeline information
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    now = datetime.now(timezone.utc)

    print(f"[*] Subject: {certificate.subject.rfc4514_string()}")
    print(f"[*] Issuer: {certificate.issuer.rfc4514_string()}")
    print(f"[*] Valid From: {not_before}")
    print(f"[*] Valid Until: {not_after}")

    # Check temporal validity
    if now < not_before:
        print("[-] CRITICAL: Certificate is not active yet (future activation date).")
    elif now > not_after:
        print("[-] CRITICAL: Certificate has EXPIRED!")
    else:
        print("[+] SUCCESS: The digital certificate is structurally valid and currently active.")

def main_menu():
    ensure_directories()
    while True:
        print("\n============================================")
        print(" DIGITAL SIGNATURE & CERTIFICATE SYSTEM")
        print("============================================")
        print("1. Sign Document")
        print("2. Verify Signature")
        print("3. Verify Certificate Validity")
        print("4. Exit")
        print("============================================")
        
        choice = input("Enter choice (1-4): ").strip()
        
        if choice == '1':
            sign_document()
        elif choice == '2':
            verify_signature()
        elif choice == '3':
            verify_certificate()
        elif choice == '4':
            print("[*] Exiting system. Goodbye.")
            sys.exit(0)
        else:
            print("[-] Invalid selection. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[*] Program interrupted. Exiting.")
        sys.exit(0)

