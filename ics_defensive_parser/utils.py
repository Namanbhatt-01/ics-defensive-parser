import re

# Regex validations to check input sanity and mitigate potential exploit vectors
IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
HEX_REGEX = re.compile(r"^[0-9a-fA-F]*$")

def is_valid_ipv4(ip_str):
    """Validates that a string conforms to a valid IPv4 address pattern (0-255 bounds)."""
    if not ip_str or not IPV4_REGEX.match(ip_str):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in ip_str.split("."))
    except ValueError:
        return False

def is_valid_hex_payload(payload_str):
    """Validates that a payload consists solely of valid hex characters (spaces ignored)."""
    if not payload_str:
        return True
    sanitized = payload_str.replace(" ", "")
    return bool(HEX_REGEX.match(sanitized))
