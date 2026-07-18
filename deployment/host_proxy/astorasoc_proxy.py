import argparse
import http.client
import socketserver
from http.server import BaseHTTPRequestHandler


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class AstoraSOCProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    backend_host = "127.0.0.1"
    backend_port = 5001

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_PUT(self):
        self.forward()

    def do_PATCH(self):
        self.forward()

    def do_DELETE(self):
        self.forward()

    def do_OPTIONS(self):
        self.forward()

    def forward(self):
        client_ip = self.client_address[0]
        body = self.read_body()
        headers = self.forward_headers(client_ip)
        connection = http.client.HTTPConnection(self.backend_host, self.backend_port, timeout=90)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() in HOP_BY_HOP_HEADERS:
                    continue
                if key.lower() == "location":
                    value = value.replace(f"http://{self.backend_host}:{self.backend_port}", f"http://{self.headers.get('Host', '')}")
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:
            message = b"AstoraSOC proxy could not reach the backend."
            self.send_response(502, "Bad Gateway")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)
            self.log_error("backend error: %s", exc.__class__.__name__)
        finally:
            connection.close()

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else None

    def forward_headers(self, client_ip):
        headers = {}
        for key, value in self.headers.items():
            if key.lower() in HOP_BY_HOP_HEADERS:
                continue
            if key.lower() == "content-length":
                continue
            headers[key] = value
        existing_forwarded = headers.get("X-Forwarded-For", "")
        chain = [part.strip() for part in existing_forwarded.split(",") if part.strip()]
        chain.append(client_ip)
        headers["X-Forwarded-For"] = ", ".join(chain)
        headers["X-Real-IP"] = client_ip
        headers["X-Forwarded-Proto"] = "http"
        headers["X-Forwarded-Host"] = self.headers.get("Host", "")
        headers["X-Forwarded-Port"] = str(self.server.server_address[1])
        return headers

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} - {fmt % args}")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="AstoraSOC host proxy for real client IP forwarding.")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=5000)
    parser.add_argument("--backend-host", default="127.0.0.1")
    parser.add_argument("--backend-port", type=int, default=5001)
    args = parser.parse_args()

    AstoraSOCProxy.backend_host = args.backend_host
    AstoraSOCProxy.backend_port = args.backend_port
    with ThreadingHTTPServer((args.listen_host, args.listen_port), AstoraSOCProxy) as server:
        print(f"AstoraSOC proxy listening on {args.listen_host}:{args.listen_port} -> {args.backend_host}:{args.backend_port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
