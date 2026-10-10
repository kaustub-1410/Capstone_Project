import socket
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class RealWorldScanner:
    """Performs real socket connections to audit open network services and gather system banners."""

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def infer_service_name(self, port: int) -> str:
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            135: "RPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Proxy"
        }
        return common_ports.get(port, f"unknown_port_{port}")

    def banner_grab(self, ip: str, port: int) -> str:
        """Attempts to read service banners from the target open socket."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            
            # If HTTP/HTTPS port, send standard request headers to get web server banner
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                response = s.recv(1024).decode('utf-8', errors='ignore')
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                return "HTTP Banner Available (No Server header)"
            
            # For other services, listen to initial connection greetings (SSH, FTP, etc.)
            banner = s.recv(512).decode('utf-8', errors='ignore').strip()
            s.close()
            if banner:
                return banner
        except Exception:
            pass
        return "Unknown Version"

    def scan_host(self, ip: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Audits target ports and gathers configuration mappings."""
        open_services = []
        logger.info(f"Scanning target IP {ip} on ports: {ports}")
        
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((ip, port))
            
            if result == 0:
                # Port is open
                logger.info(f"  [+] Port {port} is OPEN.")
                banner = self.banner_grab(ip, port)
                service_name = self.infer_service_name(port)
                open_services.append({
                    "port": port,
                    "status": "open",
                    "service": service_name,
                    "banner": banner
                })
            s.close()
            
        return open_services
