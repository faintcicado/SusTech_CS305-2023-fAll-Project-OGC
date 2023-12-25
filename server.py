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
    parser.add_argument("-p", "--port", type=int, default=8080, help="The port to listen on")
    parser.add_argument("-i", "--host", type=str, default='localhost', help="The host")
    return parser.parse_args()


class Server:
    def __init__(self, port):
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 将server绑定到指定host和port上
        self.server_socket.bind(("localhost", self.port))
        # 最多等待10个客户端的链接
        # 启动server
        self.server_socket.listen(10)

    def run(self):
        while True:
            # 返回一个用来传输数据的socket -> connection
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
            # 阻塞程序，持续接收数据
            chunk = connection.recv(1024)
            request += chunk
            # 当接收到\r\n\r\n时，报文结束
            if chunk.endswith(b"\r\n\r\n"):
                break
        return request.decode("utf-8")

    def handle_request(self, request, connection):
        request_line= request.split("\r\n", 2)[0]
        request_line = request_line.upper()
        if request_line.startswith("GET"):
            self.handle_get_request(request, connection)
        elif request_line.startswith("POST"):
            self.handle_post_request(request, connection)
        elif request_line.startswith("DELETE"):
            self.handle_delete_request(request, connection)
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))

    def handle_get_request(self, request, connection):

        request_line, request_header, request_payload = request.split("\r\n", 2)
        print ('Handling GET request')
        uri = request_line.split(" ")[1]
        if uri == "/":
            uri = "index.html"
        file_path = pathlib.Path(__file__).parent / uri
        print('file_path: %s' % file_path)
        # 检查里路径里是否存在该文件
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
    
    # add simple authentication function for this server following rfc7235
    def authenticate(self, connection):
        connection.send(self.create_response(401, "Unauthorized"))
        connection.close()
        
        return


def main():
    args = parse_args()
    server = Server(args.port)
    server.run()


if __name__ == "__main__":
    main()
