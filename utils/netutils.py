import socket

def resolve_domain(domain):
    try:
        return [info[4][0] for info in socket.getaddrinfo(domain, None)]
    except Exception:
        return []

def is_port_in_use(port: int) -> bool:
    """Return True if TCP/UDP port is already bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0
