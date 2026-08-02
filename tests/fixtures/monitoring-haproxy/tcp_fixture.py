#!/usr/bin/env python3
import argparse
import socketserver


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        self.request.sendall(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()

    with socketserver.ThreadingTCPServer((args.bind, args.port), EchoHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
