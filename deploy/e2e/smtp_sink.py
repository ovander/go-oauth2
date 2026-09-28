# Minimal SMTP sink: accepts every message and writes it to mail/<n>.eml.
import socketserver, os, sys, itertools, quopri
OUT = sys.argv[1]; counter = itertools.count(1)
class H(socketserver.StreamRequestHandler):
    def w(self, s): self.wfile.write((s + "\r\n").encode())
    def handle(self):
        self.w("220 sink ESMTP")
        while True:
            line = self.rfile.readline()
            if not line: return
            cmd = line.decode(errors="replace").strip().upper()
            if cmd.startswith(("EHLO", "HELO")): self.w("250 sink")
            elif cmd.startswith(("MAIL", "RCPT", "RSET", "NOOP")): self.w("250 OK")
            elif cmd == "DATA":
                self.w("354 go"); data = []
                while True:
                    l = self.rfile.readline()
                    if l in (b".\r\n", b".\n", b""): break
                    data.append(l[1:] if l.startswith(b"..") else l)
                raw = b"".join(data)
                head, _, body = raw.partition(b"\r\n\r\n")
                n = next(counter)
                open(os.path.join(OUT, f"{n:03d}.eml"), "wb").write(head + b"\r\n\r\n" + quopri.decodestring(body))
                self.w("250 queued")
            elif cmd == "QUIT": self.w("221 bye"); return
            else: self.w("250 OK")
class S(socketserver.ThreadingTCPServer): allow_reuse_address = True
S(("127.0.0.1", 2525), H).serve_forever()
