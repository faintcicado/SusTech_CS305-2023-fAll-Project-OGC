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
        # authenticate the username and password

        if(self.authenticate(request, connection)):
            pass
        else:
            return
            
        if request_line.startswith("GET"):
            # 将整个请求传入进行处理
            self.handle_get_request(request, connection)
        elif request_line.startswith("POST"):
            self.handle_post_request(request, connection)
        elif request_line.startswith("HEAD"):
            self.handle_head_request(request, connection)
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))

    def handle_get_request(self, request, connection):

        request_line, request_header, request_payload = self.split_request(request)
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

        # 检测目标文件类型
        content_type = mimetypes.guess_type(file_path)[0]
        if content_type is None:
            # 通用的二进制文件类型
            content_type = "application/octet-stream"
        with open(file_path, "rb") as f:
            connection.send(self.create_response(200, "OK", content_type))
            while True:
                chunk = f.read(1024)
                if not chunk:
                    print('文件读取完毕')
                    break
                # 在此处传输文件payload
                connection.send(chunk)
            print("文件发送完毕")
            print("================================================")

        if self.request_header_extractor(request_header,CON) == 'close':
            connection.close()

    def handle_post_request(self, request, connection):
        connection.send(self.create_response(200, "OK"))



    def handle_head_request(self, request, connection):
        request_line, request_header, request_payload = self.split_request(request)
        print('Handling HEAD request')
        # "GET / HTTP/1.1\r\n" 在这个情况下uri = GET 和 HTTP/1.1\r\n" 中间的 '/'

        uri = request_line.split(" ")[1]
        if uri == "/":
            uri = "index.html"
        file_path = pathlib.Path(__file__).parent / uri
        # print('file_path: %s' % file_path)

        # 检查里路径里是否存在该文件
        if not file_path.is_file():
            connection.send(self.create_response(404, "File Not Found"))
            return
        # 检测目标文件类型
        content_type = mimetypes.guess_type(file_path)[0]
        if content_type is None:
            # 通用的二进制文件类型
            content_type = "application/octet-stream"
        with open(file_path, "rb") as f:
            connection.send(self.create_response(200, "OK", content_type))

        if self.request_header_extractor(request_header, CON) == 'close':
            connection.close()


    # 将request区分为三个部分
    def split_request(self, request):
        # 先提取request_line
        request_line, request_body = request.split("\r\n", 1)
        request_header, request_payload = request_body.split("\r\n\r\n",1)
        return request_line,request_header,request_payload


    # ----------------------------------------------------------------
    # 提取一个headers中指定header的状态
    # request_header = "Connection : keep-alive\nAuthorization : Basic"
    # request_header_extractor(request_header,'Connection' ,connection)
    # 返回值：keep-alive
    # please make sure that every header is strictly splited by “ ： ”, its also level-sensitive
    # ----------------------------------------------------------------
    def request_header_extractor(self,request_header, target_header):
        # print(request_header)
        # print(target_header)
        connection_status = [i for i in request_header.splitlines() if i.startswith(target_header)][0].split(': ')[1]
        return connection_status

    def create_response(self, status_code, status_message, content_type="text/plain"):
        response = f"HTTP/1.1 {status_code} {status_message}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(response)}\r\n"
        response += "\r\n"
        return response.encode("utf-8")
    
    # add simple authentication function for this server following rfc7235
    def authenticate(self, request, connection):
        # using request_header_extractor to extract the Authorization header 
        # and then using the base64 to decode the username and password then compare with the local file (not that complicated through)
        # then return the status code to client then return true or false to the main function

        #TODO: test this function
        #TODO: how to use request_header_extractor
        request_line, request_header, request_payload = self.split_request(request)
        authorization = self.request_header_extractor(request_header, 'Authorization')
        username, password = base64.b64decode(authorization.split(' ')[1]).decode('utf-8').split(':')
        # print('username: %s\n' % username)
        # print('password: %s\n' % password)
        if username == 'client1' and password == '123': # base64 decode of Y2xpZW50MToxMjM= is client1:123
            return True
        else:
            connection.send(self.create_response(401, "Unauthorized"))
            #TODO: should i close the connection?
            return False
        


def main():
    args = parse_args()
    server = Server(args.port)
    server.run()


if __name__ == "__main__":
    main()
