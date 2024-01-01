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
import shutil

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
    request_headers = {}
    response_line = f''
    response_headers = f''
    response_payload = b''
    connection = None

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
        # 等待client链接
        while True:
            # 返回一个用来传输数据的socket -> connection
            connection, address = self.server_socket.accept()

            self.handle_connection(connection, address)

    def handle_connection(self, connection, address):
        try:
            self.connection = connection
            # self.receive_request(connection)
            while self.handle_request(self.receive_request(connection), connection):
                pass
        except Exception:
            traceback.print_exc(file=sys.stderr)
        finally:
            connection.close()

    def receive_request(self, connection):
        request = b""

        while True:
            # 阻塞程序，持续接收数据
            chunk = connection.recv(1024)
            request += chunk
            # 当接收到\r\n\r\n时，报文结束
            if chunk.endswith(b"\r\n\r\n"):
            # if chunk is None:
                break
        return request.decode()

    def handle_request(self, request, connection):

        # request_line =  "GET / HTTP/1.1\r\n"
        request_line,temp =  request.split("\r\n", 1)
        # request_headers_temp1 :
        request_headers_temp1,request_payload = temp.split("\r\n\r\n")

        request_headers_temp2 = request_headers_temp1.split("\r\n")
        for i in request_headers_temp2:
            header,value = i.split(": ")
            self.request_headers[header] = value

        # authenticate the username and password
        # 未认证的情况直接关闭链接
        if(self.authenticate(request, connection)):
            pass
        else:
            return False

        request_line = request_line.upper()
        if request_line.startswith("GET"):
            # 将整个请求传入进行处理
            self.handle_get_request(request, connection,False)
        elif request_line.startswith("POST"):
            self.handle_post_request(request, connection)
        elif request_line.startswith("HEAD"):
            self.handle_get_request(request, connection,False)
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))

    def handle_get_request(self, request, connection,isHead):

        request_line, request_header, request_payload = self.split_request(request)
        print ('Handling GET request')
        # "GET / HTTP/1.1\r\n" 在这个情况下uri = GET 和 HTTP/1.1\r\n" 中间的 '/'
        uri = request_line.split(" ")[1]

        if uri == "/":
            uri = "index.html"
        elif uri == "/teapot":
            uri = "teapot.html"
        # write a elif when uri begin with "/data/" or "data/" or "/data" or "data"
        elif uri.startswith("/data/") or uri.startswith("data/") or uri.startswith("/data") or uri.startswith("data"):
            if uri.startswith('/'): # remove the leading '/'
                uri = uri[1:]
            file_path = pathlib.Path(__file__).parent / uri
            print('file_path: %s' % file_path)

            # 检查里路径里是否存在该文件
            if file_path.exists():
                if file_path.is_file():
                    # 检测目标文件类型
                    content_type = mimetypes.guess_type(file_path)[0]
                    if content_type is None:
                        # 通用的二进制文件类型
                        content_type = "application/octet-stream"
                    with open(file_path, "rb") as f:
                        connection.send(self.create_response(200, "OK", content_type, os.path.getsize(file_path)))
                        connection.send(f.read())
                elif file_path.is_dir():
                    render_dir_html();
                else:
                    # send 404 not found
                    return
            else:
                # send 404 not found
                return
         
    def send_file(self, file_path, connection):
        # to be done
        with open(file_path, "rb") as f:
            connection.send(self.create_response(200, "OK", content_type, os.path.getsize(file_path)))
            connection.send(f.read())

    def render_dir_html(self, dir_path):
        # to be done
        html = "<html><body>"
        for file in os.listdir(dir_path):
            html += f"<a href='{file}'>{file}</a><br>"
        html += "</body></html>"
        return html
            

    def handle_post_request(self, request, connection):
        connection.send(self.create_response(200, "OK"))



    def handle_head_request(self, request, connection):
        request_line, request_header, request_payload = self.split_request(request)
        request_payload = request_payload.strip()
        print('Handling POST request')

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
    def get_request_header(self, target_header):
        if target_header not in self.request_headers:
            return False
        else:
            return self.request_headers[str(target_header)]

    # 将全局的response头修改
    def create_response_line(self,status_code,status_message):
        self.response_line = f"HTTP/1.1 {status_code} {status_message}\r\n"

    # 增加一个回复header
    def create_response_header(self,header,value):
        self.response_header += (f"{header}: {value}\r\n")

    # 结束headers的编辑
    def end_response_headers(self):
        self.response_header += (f"\r\n")
        self.flush_headers(self)

    # encode and send headers
    def flush_headers(self):
        self.connection.sendall(self.response_header.encode())

    # encode and send response_line
    def end_response_line(self):
        self.connection.sendall(self.response_line.encode())

    def create_response_payload(self,payload):
        self.response_payload.append(payload.encode())
    
    def end_response_payload(self):
        self.connection.sendall(self.response_payload)




    def read_credentials_from_json(self, file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            credentials_list = {}
            for user_data in data['users']:
                credentials_list[user_data['username']] = user_data['password']
            return credentials_list


    # add simple authentication function for this server following rfc7235
    def authenticate(self, request, connection):
        # Authenticate the client request
        request_line, request_header, request_payload = self.split_request(request)
        authorization = self.get_request_header(AUT)
        if authorization:
            username, password = base64.b64decode(authorization.split(' ')[1]).decode('utf-8').split(':')

            file_path = 'userData.json'
            credentials = self.read_credentials_from_json(file_path)
            print(username, password)
            if username in credentials and password == credentials[username]:

                print("Authentication success")
                return True
            else:
                self.create_response_line(401, "Unauthorized")
                self.end_response_line()

                print("Authentication failed")
                return False
        else:
            # connection.send(self.create_response(401, "Unauthorized"))
            self.create_response_line(401, "Unauthorized")
            self.create_response_header('WWW-Authenticated','Basic realm="Authorization Required"')
            print("缺少Aut信息")
            return False
        


def main():
    args = parse_args()
    server = Server(args.port)
    server.run()


if __name__ == "__main__":
    main()
