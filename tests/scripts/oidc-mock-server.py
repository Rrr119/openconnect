#!/usr/bin/env python3
#
# A minimal TLS VPN gateway used by the auth-oidc test to exercise
# OpenConnect's RFC 6750 HTTP Bearer (OIDC) authentication handling.
#
# Usage: oidc-mock-server.py MODE PORT OUTFILE CERT KEY [TOKEN]
#
# MODE selects how the server treats incoming requests:
#   bearer -> 401 with "WWW-Authenticate: Bearer" until the correct
#             bearer token is presented, then 200.
#   reject -> always answer 401 Bearer, even with the right token, to
#             exercise the client's failure diagnostics.
#   open   -> never challenge; answer 200 regardless of the header, to
#             exercise backwards compatibility.
#
# The server reads the raw request bytes so that it can detect a malformed
# Authorization header (for example a bare newline smuggled inside the
# header value). It writes JSON to OUTFILE describing the last request:
#   authorization : the decoded Authorization header value, or null
#   malformed     : true if a header line was not properly CRLF terminated
#   last_status   : the HTTP status returned to the client
#   requests      : list of request targets

import json
import socket
import ssl
import sys
import threading


def main():
    mode, port, outfile, cert, key = sys.argv[1:6]
    token = sys.argv[6] if len(sys.argv) > 6 else "good-token-12345"
    port = int(port)
    state = {"authorization": None, "malformed": False,
             "last_status": None, "requests": []}

    def dump():
        with open(outfile, "w") as handle:
            json.dump(state, handle)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)

    def handle(raw_conn):
        try:
            conn = context.wrap_socket(raw_conn, server_side=True)
            data = conn.recv(16384)
            text = data.decode("iso-8859-1")
            head = text.split("\r\n\r\n", 1)[0]
            lines = head.split("\r\n")

            request_target = ""
            parts = lines[0].split(" ") if lines else []
            if len(parts) >= 2:
                request_target = parts[1]
            state["requests"].append(request_target)

            auth = None
            for line in lines[1:]:
                # A bare \n inside what httplib called a line means the
                # client emitted a malformed (non-CRLF) header block.
                if "\n" in line:
                    state["malformed"] = True
                if line.lower().startswith("authorization:"):
                    auth = line.split(":", 1)[1].strip()
            state["authorization"] = auth

            if mode == "open" or (mode == "bearer" and auth == "Bearer " + token):
                status = 200
                body = b"mock gateway ok"
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n\r\n" % len(body)
                ).encode("iso-8859-1") + body
            else:
                status = 401
                response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    'WWW-Authenticate: Bearer realm="mock-vpn"\r\n'
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("iso-8859-1")

            state["last_status"] = status
            dump()
            conn.sendall(response)
            conn.close()
        except Exception:
            dump()

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    listener.settimeout(1.0)
    serve()


if __name__ == "__main__":
    main()
