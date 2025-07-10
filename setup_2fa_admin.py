import os
import pyotp
import qrcode
from dotenv import load_dotenv

def update_env_file(secret):
    """Update .env file with the new secret"""
    env_content = []
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                if not line.startswith('TOTP_SECRET='):
                    env_content.append(line)
    env_content.append(f'TOTP_SECRET={secret}\n')
    with open('.env', 'w') as f:
        f.writelines(env_content)

def display_qr_code(secret):
    """Generate and display optimized ASCII QR code"""
    # Create properly formatted TOTP URI
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name="SFS_Admin",  # No spaces for better compatibility
        issuer_name="Secure_File_Server"
    )
    
    # Optimized QR code settings
    qr = qrcode.QRCode(
        version=3,  # Fixed size for consistency
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=2,  # Larger modules for better recognition
        border=1,    # Smaller border
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    # High-contrast ASCII representation
    print("\nScan this QR code with your authenticator app:\n")
    for row in qr.modules:
        print(''.join(['██' if module else '  ' for module in row]))
    print()  # Extra newline for spacing

def verify_code(secret):
    """Handle the verification process"""
    totp = pyotp.TOTP(secret)
    attempts = 0
    while attempts < 3:
        code = input("Enter 6-digit code (or 'r' to regenerate): ").strip()
        if code.lower() == 'r':
            return False
        if len(code) == 6 and code.isdigit():
            if totp.verify(code):
                print("\n✓ Verified successfully!")
                return True
            print("✗ Invalid code. Try again.")
            attempts += 1
        else:
            print("✗ Please enter exactly 6 digits")
    return False

def main():
    load_dotenv()
    print("\n=== Secure File Server - 2FA Setup ===")
    
    while True:
        secret = pyotp.random_base32()
        update_env_file(secret)
        
        print(f"\nSecret Key: {secret}")
        display_qr_code(secret)
        
        if verify_code(secret):
            break
        print("\nGenerating new QR code...")

if __name__ == '__main__':
    main()