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
import _thread
from pathlib import Path


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
    cookie_length = 16
    # cookies -> clients
    cookie_to_username = {}
    cookie_to_lifetime = {}
    cookie_lifetime = datetime.timedelta(hours=5)
    curuser = {}

    def __init__(self, host, port):
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
            client_thread = threading.Thread(target=self.handle_connection, args=(connection,))
            client_thread.start()

    def handle_connection(self, connection):
        try:
            self.connection = connection
            while self.handle_request(connection):
                pass
        except Exception:
            traceback.print_exc(file=sys.stderr)
        finally:
            connection.close()

    def handle_request(self, connection):
        self.curuser = {}
        self.request_headers = {}
        self.response_line = f''
        self.response_headers = f''
        self.response_payload = b''

        request = b""
        # while True:
        # 阻塞程序，持续接收数据
        chunk = connection.recv(4096)
        request += chunk
        if request == b'': return False

        request = request.decode()

        self.request_line_sended = False
        # request_line =  "GET / HTTP/1.1\r\n"
        request_line, temp = request.split("\r\n", 1)
        # request_headers_temp1 :
        request_headers_temp1, request_payload = temp.split("\r\n\r\n", 1)

        request_headers_temp2 = request_headers_temp1.split("\r\n")
        for i in request_headers_temp2:
            header, value = i.split(": ")
            self.request_headers[header] = value

        # authenticate and cookie
        # 检查请求头中是否存在cookie:
        cookie_check = False
        if self.get_request_header('Cookie'):
            session_id = self.get_request_header('Cookie')[11:]
            if session_id in self.cookie_to_username:
                if datetime.datetime.utcnow() < self.cookie_to_lifetime[session_id]:
                    cookie_check = True
                else:
                    # cookie 过期
                    cookie_check = False
                    # self.create_response_line(401, 'Unauthorized')
                    # self.cookie_to_lifetime.pop(session_id)
                    # self.cookie_to_username.pop(session_id)
                    # return False

            # 不存在该cookie
            else:
                cookie_check = False
                # self.create_response_line(401, 'Unauthorized')
                # self.create_response_header('Content-Length', '0')
                # self.end_response_line()
                # self.end_response_headers()
                # return False

        # 请求头中不存在 Cookie header 或者 cookie 认证失败
        if not cookie_check:
            if (not self.authenticate(request, connection)):
                # 认证成功后set-cookie
                return False

        request_line = request_line.upper()
        if request_line.startswith("GET"):
            # 将整个请求传入进行处理
            self.handle_get_post_request(request, connection, False)
        elif request_line.startswith("POST"):
            self.handle_post_request(request, connection)
        elif request_line.startswith("HEAD"):
            self.handle_get_post_request(request, connection, True)
        else:
            connection.send(self.create_response(405, "Method Not Allowed"))
            self.create_response_header('Content-Length', '0')
            self.end_response_line()
            self.end_response_headers()

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
        request_line, request_header, request_payload = self.split_request(request)
        print('Handling GET request')
        # "GET / HTTP/1.1\r\n" 在这个情况下uri = GET 和 HTTP/1.1\r\n" 中间的 '/'

        request_line, request_header, request_payload = self.split_request(request)

        # /a.txt
        uri = request_line.split(" ")[1]
        if uri.startswith('/upload') or uri.startswith('/delete'):
            self.create_response_line(405, "Method Not Allowed")
            self.create_response_header("Content-Type", "application/octet-stream")
            self.create_response_header("Content-Length", "0")
            self.end_response_line()
            self.end_response_headers()

        query_code = None
        if "?" in uri:
            # userPath = 11912113/ query_string = SUSTech-HTTP=0
            userPath, query_string = uri.split("?")
            uri = userPath
            # query_string = 0
            SUSTech, query_code = query_string.split("=")

            # invalid query string
            if not (SUSTech == 'SUSTech-HTTP'):
                # 异常的查询信息
                self.create_response_line(400, 'Bad Request')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()

        # 不包含 SUSTech-HTTP=的情况

        # if uri == "/":
        #     temp = "data/"
        #     file_path = pathlib.Path(__file__).parent / temp
        #     # print('file_path: %s' % file_path)
        #     # self.send_file(file_path, connection)
        #     html = self.render_dir_html(file_path)
        #     # save  the html into temp.html
        #     with open('temp.html', 'w') as f:
        #         f.write(html)
        #     self.send_file("temp.html", connection,isHead)
        #
        # elif uri == "/teapot":
        #     temp = "teapot.html"
        #     file_path = pathlib.Path(__file__).parent / temp
        #     print('file_path: %s' % file_path)
        #     self.send_file(file_path, connection,isHead)
        #     # write a elif when uri begin with "/data/" or "data/" or "/data" or "data"
        #
        # elif uri == "/favicon.ico":
        #     temp = "favicon.ico"
        #     file_path = pathlib.Path(__file__).parent / temp
        #     print('file_path: %s' % file_path)
        #     self.send_file(file_path, connection,isHead)

        if uri.startswith('/'):
            temp_path = str(pathlib.Path(__file__).parent)
            file_path = temp_path + '/data'
            file_path = file_path +  uri
            file_path = pathlib.Path(file_path)

            # 检查里路径里是否存在该文件
            if file_path.exists():
                # 如果是file
                if file_path.is_file():
                    # 检测文件类型
                    content_type = mimetypes.guess_type(file_path)[0]
                    content_size = os.path.getsize(file_path)
                    if content_type is None:
                        # 默认的文件类型
                        content_type = "application/octet-stream"
                    with open(file_path, "rb") as f:
                        self.create_response_line(200,'OK')
                        self.create_response_header('Content-Type', content_type)
                        self.create_response_header('Content-Length',content_size)
                        self.end_response_line()
                        self.end_response_headers()
                        if not isHead:
                            self.create_response_payload(f.read())
                            self.end_response_payload()

                # 如果是dir
                elif file_path.is_dir():
                    # SUSTech-HTTP = 1 case:

                    if query_code == '1':
                        list = self.get_dir_list(file_path)
                        # 读取目录下的文件
                        self.create_response_line(200, 'OK')
                        self.create_response_header('Content-Type', 'application/octet-stream')
                        self.create_response_header('Content-Length', len(str(list).encode()))
                        # self.create_response_payload(str(list))
                        self.end_response_line()
                        self.end_response_headers()
                        # self.end_response_payload()
                        if not isHead:
                            self.create_response_payload(str(list))
                            self.end_response_payload()

                    #  SUSTech-HTTP = 0 or default case:
                    else:
                        html = self.render_dir_html(file_path)
                        # save  the html into temp.html
                        with open('temp.html', 'w') as f:
                            f.write(html)
                        self.send_file("temp.html", connection,isHead)
                else:
                    self.create_response_line(404, "Not found")
                    self.create_response_header("Content-Type", "application/octet-stream")
                    self.create_response_header("Content-Length", "0")
                    self.end_response_line()
                    self.end_response_headers()
                    return
            else:
                # 文件不存在
                self.create_response_line(404, "Not found")
                self.create_response_header("Content-Type", "application/octet-stream")
                self.create_response_header("Content-Length", "0")
                self.end_response_line()
                self.end_response_headers()
                return

        else:
            # uri 不以/开头的情况
            self.create_response_line(404, "Not found")
            self.create_response_header("Content-Type", "application/octet-stream")
            self.create_response_header("Content-Length", "0")
            self.end_response_line()
            self.end_response_headers()
            return

    def send_file(self, file_path, connection, isHead):
        with open(file_path, "rb") as f:
            self.create_response_line(200, "OK")
            self.create_response_header("Content-Length", os.path.getsize(file_path))
            self.create_response_header("Content-Type", mimetypes.guess_type(file_path)[0])

            self.end_response_line()
            self.end_response_headers()
            if not isHead:
                self.create_response_payload(f.read())
                self.end_response_payload()

    def send_response_header(self, header, value):
        self.create_response_header(header, value)
        self.end_response_headers()

    def send_response_line(self, status_code, status_message):
        self.create_response_line(status_code, status_message)
        self.end_response_line()

    def get_dir_list(self, dir_path): # example return: ["123.png", "666/", "abc.py", "favicon.ico"]
        dir_list = []
        for file in os.listdir(dir_path):
            if os.path.isdir(os.path.join(dir_path, file)):
                file += "/"
            dir_list.append(file)
        return dir_list
        


    def render_dir_html(self, dir_path):
        # to be done
        html = "<html><head><title>Directory Listing</title></head><body>"
        if dir_path != "/":
            html += "<a href='../'>../</a><br>"
        for file in os.listdir(dir_path):
            if os.path.isdir(os.path.join(dir_path, file)):
                file += "/"
            html += f"<a href='{file}'>{file}</a><br>"
        html += "</body></html>"
        return html

    def handle_post_request(self, request, connection):
        request_line, request_header, request_payload = self.split_request(request)
        print('Handling POST request')
        uri = request_line.split(" ")[1]
        if not (uri.startswith('/upload') or uri.startswith('/delete')):
            self.create_response_line(405, 'Method Not Allowed')
            self.create_response_header('Content-Length', '0')
            self.end_response_line()
            self.end_response_headers()
            return False

        if uri.startswith('/upload'):
            # 检测头部中是否包含 ? path
            if ('?' not in uri or 'path' not in uri):
                self.create_response_line(400, 'Bad Request')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                return False

            # upload?path= /11912113/
            # value： /11912113/
            # temp: 11912113/
            value = uri.split('=')[1]
            temp = ''
            if value.startswith('/'):
                temp = value.split('/', 1)[1]
            else:
                temp = value
            target_file = './data/' + temp
            path = Path(target_file)

            # 检测是否访问的时自己的dir
            if not temp.startswith(self.curuser['username']):
                self.create_response_line(403, 'Forbidden')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                return False

            # 检测访问的dir是否存在
            if not path.exists():
                self.create_response_line(404, 'Not Found')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                return False

            # POST /upload?path=client2/ HTTP/1.1
            # Host: 127.0.0.1:8080
            # User-Agent: python-requests/2.28.2
            # Accept-Encoding: gzip, deflate
            # Accept: */*
            # Connection: keep-alive
            # Authorization: Basic Y2xpZW50MToxMjM=
            # Content-Length: 157
            # Content-Type: multipart/form-data; boundary=c253942774d70f82c4c368d2b740b346

            # --c253942774d70f82c4c368d2b740b346
            # Content-Disposition: form-data; name="firstFile"; filename="a.txt"

            # sadfsdfasdf
            # --c253942774d70f82c4c368d2b740b346--

            content_type = self.get_request_header('Content-Type')
            boundary = '--' + content_type.split('=')[1]
            content = request_payload.split(boundary)
            '''
            data_raw的值
            Content - Disposition: form - data;
            name = "firstFile";
            filename = "a.txt"

            sadfsdfasdf
            '''
            data_raw = content[1].strip("\r\n")
            if len(data_raw.split('\r\n\r\n')) > 1:
                head, data = data_raw.split("\r\n\r\n", 1)
            else:
                head, data = data_raw, ''

            filename = head.split("filename=")[1].strip('"')

            with open(target_file + filename, 'w') as f:
                f.write(data)

            self.create_response_line(200, "OK")
            self.create_response_header('Content-Length', '0')
            self.end_response_line()
            self.end_response_headers()


        elif uri.startswith('/delete'):
            # 检测头部中是否包含 ? path
            if ('?' not in uri or 'path' not in uri):
                self.create_response_line(400, 'Bad Request')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                return False

            # upload?path=/11912113/a.py
            # value： /11912113/a.py
            # temp: 11912113/a.py
            value = uri.split('=')[1]
            temp = ''
            if value.startswith('/'):
                temp = value.split('/', 1)[1]
            else:
                temp = value
            target_file = './data/' + temp
            path = Path(target_file)

            # 检测是否访问的时自己的dir
            if not temp.startswith(self.curuser['username']):
                self.create_response_line(403, 'Forbidden')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                return False

            # 检测访问的dir是否存在
            if not path.exists():
                self.create_response_line(404, 'Not Found')
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                return False

            os.remove(path)
            self.create_response_line(200, "OK")
            self.create_response_header('Content-Length', '0')
            self.end_response_line()
            self.end_response_headers()

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
        request_header, request_payload = request_body.split("\r\n\r\n", 1)
        return request_line, request_header, request_payload

    # ----------------------------------------------------------------
    # 提取一个headers中指定header的状态
    def get_request_header(self, target_header):
        if target_header not in self.request_headers:
            return False
        else:
            return self.request_headers[str(target_header)]

    # 将全局的response头修改
    def create_response_line(self, status_code, status_message):
        self.response_line = f"HTTP/1.1 {status_code} {status_message}\r\n"

    # 增加一个回复header
    def create_response_header(self, header, value):
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

    def set_cookie(self, username):
        temp_cookie = self.generate_random_cookie()
        self.cookie_to_username[temp_cookie] = username
        temp_cookie_lifetime = datetime.datetime.utcnow() + self.cookie_lifetime
        self.cookie_to_lifetime[temp_cookie] = temp_cookie_lifetime
        # 编辑Set-Cookie header
        self.create_response_header('Set-Cookie', f'session-id={temp_cookie};Expires={temp_cookie_lifetime}')

    # add simple authentication function for this server following rfc7235
    def authenticate(self, request, connection):
        # Authenticate the client request
        authorization = self.get_request_header(AUT)
        if authorization:
            username, password = base64.b64decode(authorization.split(' ')[1]).decode('utf-8').split(':')

            file_path = 'userData.json'
            credentials = self.read_credentials_from_json(file_path)
            print(username, password)
            if username in credentials and password == credentials[username]:
                self.curuser['username'] = username
                self.curuser['password'] = password
                self.set_cookie(username)

                print(f"User:{username} Authentication success")
                return True

            else:
                # 登录信息不存在userData.json中,或者密码错误
                self.create_response_line(401, "Unauthorized")
                self.create_response_header('Content-Length', '0')
                self.end_response_line()
                self.end_response_headers()
                print("Authentication failed")
                return False
        else:
            # request中没有authorization信息
            self.create_response_line(401, "Unauthorized")
            self.create_response_header('WWW-Authenticate', 'Basic realm="Authorization Required"')
            self.create_response_header('Connection', 'keep-alive')
            self.create_response_header('Content-Length', '0')
            self.end_response_line()
            self.end_response_headers()
            # print("缺少Aut信息")
            return False


def main():
    args = parse_args()
    server = Server(args.host, args.port)
    server.run()


if __name__ == "__main__":
    main()
