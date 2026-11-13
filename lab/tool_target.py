"""Owned HTTP/TLS, FTP and controlled DNS lab endpoints without public ports."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "http://198.51.100.1/")
        self.end_headers()
        self.wfile.write(b"<title>Owned ScanRunner Lab</title>")


def dns(port, recursion):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", port))
        while True:
            request, peer = server.recvfrom(4096)
            if len(request) < 17:
                continue
            answer = recursion and bool(request[2] & 1)
            response = request[:2] + struct.pack("!HHHHH", 0x8180 if answer else 0x8085, 1, int(answer), 0, 0) + request[12:]
            if answer:
                response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.9")
            server.sendto(response, peer)


def main():
    processes = []
    Path("/srv/ftp").mkdir(parents=True, exist_ok=True)
    Path("/var/run/vsftpd/empty").mkdir(parents=True, exist_ok=True)
    for port, anonymous in ((21, "YES"), (2121, "NO")):
        config = Path(f"/tmp/vsftpd-{port}.conf")
        config.write_text(f"listen=YES\nlisten_ipv6=NO\nlisten_port={port}\nbackground=NO\nanonymous_enable={anonymous}\nlocal_enable=YES\nwrite_enable=NO\nno_anon_password=YES\nanon_root=/srv/ftp\nsecure_chroot_dir=/var/run/vsftpd/empty\nseccomp_sandbox=NO\n")
        processes.append(subprocess.Popen(["/usr/sbin/vsftpd", str(config)]))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=owned.invalid",
                    "-keyout", "/tmp/key.pem", "-out", "/tmp/cert.pem"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for port, tls in ((8080, False), (8443, True)):
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    for port, recursive in ((53, True), (5353, False)):
        threading.Thread(target=dns, args=(port, recursive), daemon=True).start()
    print("Owned protocol targets ready", flush=True)
    for process in processes:
        if process.wait() != 0:
            raise RuntimeError("Owned FTP service exited")


if __name__ == "__main__":
    main()
