"""Worker-side model transport. Only the external broker possesses credentials.

This gateway runs inside the worker's isolated network namespace. The broker
must independently enforce its operation boundary: worker code can access the
Unix socket directly and is never trusted merely because it uses this gateway.
"""
import http.client
import http.server
import socket
import subprocess
import threading

MAX_REQUEST = 8 * 1024 * 1024


class Gateway(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/v1/responses" or self.headers.get("Transfer-Encoding"):
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_REQUEST:
            self.send_error(413)
            return
        connection = http.client.HTTPConnection("localhost", timeout=60)
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.settimeout(60)
        try:
            connection.sock.connect("/broker/model.sock")
            connection.request("POST", "/v1/responses", self.rfile.read(length),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            self.send_response(response.status)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            total = 0
            while chunk := response.read1(65536):
                total += len(chunk)
                if total > 16 * 1024 * 1024:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
            self.close_connection = True
        except (OSError, http.client.HTTPException):
            self.close_connection = True
        finally:
            connection.close()


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), Gateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = subprocess.run(["/runtime/worker", "run", "/request.json", "/workspace/result.json"],
                                stdin=subprocess.DEVNULL)
    finally:
        server.shutdown()
        server.server_close()
    raise SystemExit(result.returncode)
