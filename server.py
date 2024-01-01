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
import secrets
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
    users = set()
    cookie_length = 16
    # cookies -> clients
    cookie_to_username = {}
    cookie_to_lifetime = {}
    cookie_lifetime = datetime.timedelta(seconds=5)

    def __init__(self,host, port):
        print(f"Server working on {host} {port}")

        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 将server绑定到指定host和port上
        self.server_socket.bind((host, port))
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

        # while True:
            # 阻塞程序，持续接收数据
        chunk = connection.recv(4096)
        request += chunk
            # 当接收到\r\n\r\n时，报文结束
            # if chunk.endswith(b"\r\n\r\n"):
            # if chunk is None:
            #     break
        return request.decode()

    def handle_request(self, request, connection):
        self.request_line_sended = False
        # request_line =  "GET / HTTP/1.1\r\n"
        request_line,temp =  request.split("\r\n", 1)
        # request_headers_temp1 :
        request_headers_temp1,request_payload = temp.split("\r\n\r\n")

        request_headers_temp2 = request_headers_temp1.split("\r\n")
        for i in request_headers_temp2:
            header,value = i.split(": ")
            self.request_headers[header] = value

        # authenticate and cookie
        # 检查请求头中是否存在cookie:

        if not ('mozilla' in self.get_request_header('User-Agent').lower()):
            if self.get_request_header('Cookie'):
                session_id = self.get_request_header('Cookie')[11:]
                if session_id in self.cookie_to_username:
                    if session_id in self.cookie_to_lifetime and datetime.datetime.utcnow() > self.cookie_to_lifetime[session_id]:
                        pass
                    else:
                        print("\ncookie过期 返回401 或者 不存在该cookie(cookie_to_lifetime)")
                        self.create_response_line(401,'Unauthorized')
                        self.cookie_to_lifetime.pop(session_id)
                        self.cookie_to_username.pop(session_id)
                # invalid cookie
                else:
                    self.create_response_line(401,'Unauthorized')

            # 请求头中不存在 Cookie header
            elif(not self.authenticate(request, connection)):
                # 认证成功后set-cookie
                return False


        request_line = request_line.upper()
        if request_line.startswith("GET"):
            # 将整个请求传入进行处理
            self.handle_get_post_request(request, connection,False)
        elif request_line.startswith("POST"):
            self.handle_post_request(request, connection)
        elif request_line.startswith("HEAD"):
            self.handle_get_post_request(request, connection,False)
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))



        # 检测是否要关闭链接
        if self.get_request_header(CON).lower() == 'keep-alive':
            return True
        else:
            return False

    def generate_random_cookie(self):
        while True:
            temp_cookie = secrets.token_hex(self.cookie_length)
            if temp_cookie not in self.cookie_to_username:
                return temp_cookie



    def handle_get_post_request(self, request, connection, isHead):
        print ('Handling GET request')
        # "GET / HTTP/1.1\r\n" 在这个情况下uri = GET 和 HTTP/1.1\r\n" 中间的 '/'

        request_line, request_header, request_payload = self.split_request(request)
        print (f'{request_line}')
        print (f'{request_header}')
        print (f'{request_payload}')
        
        uri = request_line.split(" ")[1]
        if uri == "/":
            uri = "index.html"    
            file_path = pathlib.Path(__file__).parent / uri
            print('file_path: %s' % file_path)
            self.send_file(file_path, connection)    
            
        elif uri == "/teapot":
            uri = "teapot.html"
            file_path = pathlib.Path(__file__).parent / uri
            print('file_path: %s' % file_path)
            self.send_file(file_path, connection)  
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
                    content_size = os.path.getsize(file_path)
                    if content_type is None:
                        # 通用的二进制文件类型
                        content_type = "application/octet-stream"
                    with open(file_path, "rb") as f:
                        connection.send(self.create_response(200, "OK", content_type, content_size))
                        connection.send(f.read())
                elif file_path.is_dir():
                    pass
                    # render_dir_html();
                else:
                    # send 404 not found
                    return
            else:
                # send 404 not found
                return
        elif uri == "/favicon.ico":
            uri = "favicon.ico"
            file_path = pathlib.Path(__file__).parent / uri
            print('file_path: %s' % file_path)
            self.send_file(file_path, connection)
        else:
            self.create_response_line(404, "Not found")
            self.create_response_header("Content-Type", "application/octet-stream")
            self.create_response_header("Content-Length", "0")
            self.create_response_payload(f.read())
            self.end_response_line()
            self.end_response_headers()
            self.end_response_payload()
            return


    def send_file(self, file_path, connection):
        with open(file_path, "rb") as f:
            self.create_response_line(200, "OK")
            self.create_response_header("Content-Length", os.path.getsize(file_path))
            self.create_response_header("Content-Type", mimetypes.guess_type(file_path)[0])
            self.create_response_payload(f.read())
            self.end_response_line()
            self.end_response_headers()
            self.end_response_payload()

    def send_response_header(self, header, value):
        self.create_response_header(header, value)
        self.end_response_headers()
        
    def send_response_line(self, status_code, status_message):
        self.create_response_line(status_code, status_message)
        self.end_response_line()

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
        # to be done
        return


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
        self.response_headers = self.response_headers + (f"{header}: {value}\r\n")

    # 结束headers的编辑
    def end_response_headers(self):
        if self.request_line_sended:
            self.response_headers = self.response_headers + (f"\r\n")
            self.flush_headers()
            self.response_headers = f''
        else:
            print("Error: Response headers should be sent after response line has been sent")

    # encode and send headers
    def flush_headers(self):
        self.connection.sendall(self.response_headers.encode())

    # encode and send response_line
    def end_response_line(self):
        self.connection.sendall(self.response_line.encode())
        self.request_line_sended = True
        self.response_line = f''

    def create_response_payload(self, payload):
        if isinstance(payload, str):
            self.response_payload += payload.encode('utf-8')
        elif isinstance(payload, bytes):
            self.response_payload += payload
        else:
            raise ValueError("Invalid payload type. Expected string or bytes.")

    def end_response_payload(self):
            self.connection.sendall(self.response_payload)
            self.response_payload = b''



    def read_credentials_from_json(self, file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            credentials_list = {}
            for user_data in data['users']:
                credentials_list[user_data['username']] = user_data['password']
            return credentials_list

    def set_cookie(self,username):
        temp_cookie = self.generate_random_cookie()
        self.cookie_to_username[temp_cookie] = username
        temp_cookie_lifetime = datetime.datetime.utcnow() + self.cookie_lifetime
        self.cookie_to_lifetime[temp_cookie] = temp_cookie_lifetime
        # 编辑Set-Cookie header
        self.create_response_header('Set-Cookie',f'session-id={temp_cookie};Expires={temp_cookie_lifetime}')



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
                self.set_cookie(username)

                print(f"User:{username} Authentication success")
                return True
            else:
                # 登录信息不存在userData.json中,或者密码错误
                self.create_response_line(401, "Unauthorized")
                self.end_response_line()
                print("Authentication failed")
                return False
        else:
            # request中没有authorization信息
            self.create_response_line(401, "Unauthorized")
            self.create_response_header('WWW-Authenticated','Basic realm="Authorization Required"')
            self.end_response_line()
            self.end_response_headers()
            print("缺少Aut信息")
            return False

def main():
    args = parse_args()
    server = Server(args.host,args.port)
    server.run()


if __name__ == "__main__":
    main()
