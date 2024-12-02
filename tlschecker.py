import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

# ANSI escape codes for color
class Colors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

def format_datetime(dt: datetime) -> str:
    """Formats datetime in a human-readable form."""
    return dt.strftime("%A %d %B %Y at %H:%M:%S %Z")

def get_tls_certificate(hostname: str, port: int = 443):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    
    try:
        conn.connect((hostname, port))
        cert_bin = conn.getpeercert(True)
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        return cert
    except Exception as e:
        print(f"{Colors.FAIL}Error retrieving TLS certificate: {e}{Colors.ENDC}")
        return None
    finally:
        conn.close()

def display_certificate_info(cert: x509.Certificate):
    print(f"\n{Colors.HEADER}=== Certificate Information ==={Colors.ENDC}")
    print(f"{Colors.BOLD}Issued To:{Colors.ENDC} {cert.subject.rfc4514_string()}")
    print(f"{Colors.BOLD}Issued By:{Colors.ENDC} {cert.issuer.rfc4514_string()}")
    print(f"{Colors.BOLD}Serial Number:{Colors.ENDC} {hex(cert.serial_number)}")
    print(f"{Colors.BOLD}Valid From:{Colors.ENDC} {format_datetime(cert.not_valid_before_utc)}")
    print(f"{Colors.BOLD}Valid Until:{Colors.ENDC} {format_datetime(cert.not_valid_after_utc)}")
    print(f"{Colors.BOLD}Signature Algorithm:{Colors.ENDC} {cert.signature_algorithm_oid._name}")
    
    key = cert.public_key()
    if hasattr(key, "key_size"):
        print(f"{Colors.BOLD}Key Size:{Colors.ENDC} {key.key_size} bits")
    
    # Clean and formatted extension printing
    print(f"\n{Colors.HEADER}=== Certificate Extensions ==={Colors.ENDC}")
    for ext in cert.extensions:
        ext_name = ext.oid._name
        ext_value = ext.value
        print(f"{Colors.BOLD}- {ext_name}:{Colors.ENDC}")
        print(f"  {ext_value}\n")

def report_issues(cert: x509.Certificate):
    issues = []
    current_time = datetime.now(timezone.utc)
    
    # Check expiry
    if current_time > cert.not_valid_after_utc:
        issues.append(f"{Colors.FAIL}Certificate is expired.{Colors.ENDC}")
    if current_time < cert.not_valid_before_utc:
        issues.append(f"{Colors.WARNING}Certificate is not yet valid.{Colors.ENDC}")
    
    # Check key size (weak keys)
    key = cert.public_key()
    if hasattr(key, "key_size") and key.key_size < 2048:
        issues.append(f"{Colors.FAIL}Weak key size detected (less than 2048 bits).{Colors.ENDC}")

    # Check weak signature algorithms
    weak_algorithms = ("md5", "sha1")
    if cert.signature_hash_algorithm.name.lower() in weak_algorithms:
        issues.append(f"{Colors.FAIL}Weak hash algorithm used: {cert.signature_hash_algorithm.name}{Colors.ENDC}")

    # Check for wildcard in the Common Name (CN)
    common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if "*" in common_name:
        issues.append(f"{Colors.WARNING}Wildcard in Common Name detected.{Colors.ENDC}")

    # Check if it's self-signed
    if cert.issuer == cert.subject:
        issues.append(f"{Colors.WARNING}Self-signed certificate detected.{Colors.ENDC}")

    return issues

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"{Colors.FAIL}Usage: python check_tls.py <hostname>{Colors.ENDC}")
        sys.exit(1)

    hostname = sys.argv[1]
    cert = get_tls_certificate(hostname)
    
    if cert:
        display_certificate_info(cert)
        
        issues = report_issues(cert)
        if issues:
            print(f"\n{Colors.FAIL}Potential Issues Detected:{Colors.ENDC}")
            for issue in issues:
                print(f"- {issue}")
        else:
            print(f"\n{Colors.OKGREEN}No significant issues detected.{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}Failed to retrieve TLS certificate.{Colors.ENDC}")
