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
import base64

def parse_args():
    parser = argparse.ArgumentParser(description="Simple file manager server")
    parser.add_argument("-p", "--port", type=int, default=8080, help="The port to listen on")
    parser.add_argument("-i", "--host", type=str, default='localhost', help="The host")
    return parser.parse_args()

# - Content-Type: the size of the message body, in bytes
# - Content-Length: the original media type of the resource
# - Connection: whether the network connection stays open after the current transaction finishes
# - Set-Cookie / Cookie: addition information from server to client / client to server
# - WWW-Authentication / Authorization: server requests authentication from client / client provides credentials for server
# - Transfer-Encoding: the form of encoding used to safely transfer the payload body to user
# - Range / Content-Range: specify content range (bytes in default) when request partial content
CT = 'Content-Type'
CL = 'Content-Length'
CON = 'Connection'
ST = 'Set-Cookie'
CK = 'Cookie'
AUT = 'Authorization'
TE = 'Transfer-Encoding'
CR = 'Content-Range'

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
        # request_line =  "GET / HTTP/1.1\r\n"
        request_line= request.split("\r\n", 2)[0]
        request_line = request_line.upper()
        if request_line.startswith("GET"):
            # 将整个请求传入进行处理
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
        # "GET / HTTP/1.1\r\n" 在这个情况下uri = GET 和 HTTP/1.1\r\n" 中间的 '/'
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
            # 通用的二进制文件类型
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

    # ----------------------------------------------------------------
    # 提取一个headers中指定header的状态
    # request_header = "Connection : keep-alive\nAuthorization : Basic"
    # request_header_checkConnection(request_header,'Connection' ,connection)
    # 返回值：keep-alive
    # please make sure that every header is strictly splited by “ ： ”, its also level-sensitive
    # ----------------------------------------------------------------
    def request_header_extractor(request_header, target_header, connection):
        connection_status = [i for i in request_header.splitlines() if i.startswith(target_header)][0].split(' : ')[1]
        return connection_status

    def create_response(self, status_code, status_message, content_type="text/plain"):
        response = f"HTTP/1.1 {status_code} {status_message}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(response)}\r\n"
        response += "\r\n"
        return response.encode("utf-8")
    
    # add simple authentication function for this server following rfc7235
    def authenticate(self, connection):
        # get the authentication information from the client
        request = self.receive_request(connection)
        request_line, request_header, request_payload = request.split("\r\n", 2)
        print(request_line, request_header, request_payload)
        request_line = request_line.upper()
        if request_line.startswith("GET"):
            uri = request_header
        elif request_line.startswith("POST"):
            uri = request_header
        elif request_line.startswith("DELETE"):
            uri = request_header
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))
            return
        # get the username and password from the uri
        username = uri.split('&')[0].split('=')[1]
        password = uri.split('&')[1].split('=')[1]
        # get the authentication information from the server
        with open('auth.json', 'r') as f:
            auth = json.load(f)
        # check the authentication information
        if username in auth.keys() and password == auth[username]:
            connection.send(self.create_response(200, "OK"))
            return
        else:# if the authentication information is wrong, send 401 Unauthorized
            connection.send(self.create_response(401, "Unauthorized"))
            return
        return


def main():
    args = parse_args()
    server = Server(args.port)
    server.run()


if __name__ == "__main__":
    main()
