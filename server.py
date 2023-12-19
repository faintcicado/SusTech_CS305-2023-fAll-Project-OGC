import argparse
import socket
import mimetypes
import io
import sys
import time
import datetime
import os
import signal
import threading
import pathlib
import traceback
import json


def parse_args():
    parser = argparse.ArgumentParser(description="Simple file manager server")
    parser.add_argument("-p", "--port", type=int, default=8000, help="The port to listen on")
    return parser.parse_args()


class FileManagerServer:
    def __init__(self, port):
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("localhost", self.port))
        self.server_socket.listen(10)

    def run(self):
        while True:
            connection, address = self.server_socket.accept()
            self.handle_connection(connection, address)

    def handle_connection(self, connection, address):
        try:
            request = self.receive_request(connection)
            self.handle_request(request, connection)
        except Exception:
            traceback.print_exc(file=sys.stderr)

    def receive_request(self, connection):
        request = b""
        while True:
            chunk = connection.recv(1024)
            request += chunk
            if chunk.endswith(b"\r\n\r\n"):
                break
        return request.decode("utf-8")

    def handle_request(self, request, connection):
        method, uri, headers = request.split("\r\n", 2)
        method = method.upper()
        if method == "GET":
            self.handle_get_request(uri, connection)
        elif method == "POST":
            self.handle_post_request(uri, connection)
        elif method == "DELETE":
            self.handle_delete_request(uri, connection)
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))

    def handle_get_request(self, uri, connection):
        if uri == "/":
            uri = "index.html"
        file_path = pathlib.Path(__file__).parent / uri
        if not file_path.is_file():
            connection.send(self.create_response(404, "File Not Found"))
            return
        content_type = mimetypes.guess_type(file_path)[0]
        if content_type is None:
            content_type = "application/octet-stream"
        with open(file_path, "rb") as f:
            connection.send(self.create_response(200, "OK", content_type))
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                connection.send(chunk)

    def handle_post_request(self, uri, connection):
        pass

    def handle_delete_request(self, uri, connection):
        pass

    def create_response(self, status_code, status_message, content_type="text/plain"):
        response = f"HTTP/1.1 {status_code} {status_message}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(response)}\r\n"
        response += "\r\n"
        return response.encode("utf-8")


def main():
    args = parse_args()
    server = FileManagerServer(args.port)
    server.run()


if __name__ == "__main__":
    main()
