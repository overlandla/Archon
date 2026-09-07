"""Worker-side Git smart-HTTP transport to the repository-scoped read broker."""
import http.client
import http.server
import socket


class GitGateway(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        paths = {("GET", "/repository.git/info/refs?service=git-upload-pack"),
                 ("POST", "/repository.git/git-upload-pack")}
        if (self.command, self.path) not in paths or self.headers.get("Transfer-Encoding"):
            self.send_error(403)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else None
        connection = http.client.HTTPConnection("localhost", timeout=30)
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.settimeout(30)
        try:
            connection.sock.connect("/broker/git.sock")
            connection.request(self.command, self.path, body, {"Content-Type": "application/x-git-upload-pack-request"})
            response = connection.getresponse()
            self.send_response(response.status)
            self.send_header("Content-Type", "application/x-git-upload-pack-advertisement" if self.command == "GET" else "application/x-git-upload-pack-result")
            self.send_header("Connection", "close")
            self.end_headers()
            total = 0
            while chunk := response.read1(65536):
                total += len(chunk)
                if total > 64 * 1024 * 1024:
                    raise RuntimeError("git_response_too_large")
                self.wfile.write(chunk)
            self.close_connection = True
        finally:
            connection.close()
