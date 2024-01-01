# 文档提供的库
import socket
import threading
import os
import argparse
import signal
import sys
import time
import mimetypes

# 其他
from enum import IntEnum, Enum
from dataclasses import dataclass
import base64
import secrets

# RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pd_rsa

# AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as pd_aes

DEBUG = True  # 是否开启调试模式
ROOT = "data/"  # 文件根目录
TOCKEN_EXPIRE_TIME = 5  # tocken过期时间, 单位秒
CHUNK_SIZE = 8  # 使用chunk传输文件时每次传输的大小, 单位字节

# 生成密钥对
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
PUBLIC_KEY = PRIVATE_KEY.public_key()


@dataclass
class UserInfo:
    username: str
    password: str
    tocken: str
    tocken_expire_time: int


class Users(Enum):
    USER1 = UserInfo("user1", "1", "", 0)
    USER2 = UserInfo("user2", "2", "", 0)
    USER3 = UserInfo("user3", "3", "", 0)
    USER4 = UserInfo("client1", "123", "", 0)
    USER5 = UserInfo("client2", "123", "", 0)
    USER6 = UserInfo("client3", "123", "", 0)

    @property
    def username(self):
        return self.value.username

    @property
    def password(self):
        return self.value.password

    @property
    def tocken(self):
        return self.value.tocken

    @property
    def tocken_expire_time(self):
        return self.value.tocken_expire_time

    @tocken.setter
    def tocken(self, value):
        self.value.tocken = value

    @tocken_expire_time.setter
    def tocken_expire_time(self, value):
        self.value.tocken_expire_time = value


class HTTPStatus(IntEnum):
    def __new__(cls, value, phrase, description=""):
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.phrase = phrase
        obj.description = description
        return obj

    # informational
    CONTINUE = 100, "Continue", "Request received, please continue"
    SWITCHING_PROTOCOLS = (
        101,
        "Switching Protocols",
        "Switching to new protocol; obey Upgrade header",
    )
    PROCESSING = 102, "Processing"
    EARLY_HINTS = 103, "Early Hints"

    # success
    OK = 200, "OK", "Request fulfilled, document follows"
    PARTIAL_CONTENT = 206, "Partial Content", "Partial content follows"

    # redirection
    MOVED_PERMANENTLY = (
        301,
        "Moved Permanently",
        "Object moved permanently -- see URI list",
    )

    # client error
    BAD_REQUEST = (400, "Bad Request", "Bad request syntax or unsupported method")
    UNAUTHORIZED = (401, "Unauthorized", "No permission -- see authorization schemes")
    FORBIDDEN = (403, "Forbidden", "Request forbidden -- authorization will not help")
    NOT_FOUND = (404, "Not Found", "Nothing matches the given URI")
    METHOD_NOT_ALLOWED = (
        405,
        "Method Not Allowed",
        "Specified method is invalid for this resource",
    )
    REQUESTED_RANGE_NOT_SATISFIABLE = (
        416,
        "Requested Range Not Satisfiable",
        "Cannot satisfy request range",
    )

    # server errors
    INTERNAL_SERVER_ERROR = (
        500,
        "Internal Server Error",
        "Server got itself in trouble",
    )
    NOT_IMPLEMENTED = (501, "Not Implemented", "Server does not support this operation")
    BAD_GATEWAY = (502, "Bad Gateway", "Invalid responses from another server/proxy")
    SERVICE_UNAVAILABLE = (
        503,
        "Service Unavailable",
        "The server cannot process the request due to a high load",
    )


class BaseHTTPRequestHandler:
    def __init__(self, client_socket: socket, client_address):
        self.client_socket = client_socket
        self.client_address = client_address

        self.user: UserInfo = None

        self.request_line = None
        self.request_method = None
        self.request_url = None
        self.request_path = None
        self.request_params = {}
        self.request_httpVersion = None
        self.request_headers = {}
        self.request_body = None

        self.response_headers = []

        self.aes = None

    def handle_request(self):
        """
        handle one request
        Note:
        1. decode all request data
        2. recieive all entity body
        3. parse request line, headers, body
        4. check authorization
        5. call do_{method} to handle request
        6. persistent connection
        """
        SIZE = 2048
        try:
            raw_request = self.client_socket.recv(SIZE)
            print(raw_request)
            if raw_request == b"":  # socket is closed
                return False
            if raw_request.startswith(b"ENCRYPTED"):
                self.aes = EncryptorServer(self.client_socket).handle_request()
                return True
            request_line, rest = raw_request.split(b"\r\n", 1)
            raw_headers, raw_body = rest.split(b"\r\n\r\n", 1)
        except ValueError as e:
            print(e)
            # 有时会收到空请求, 这里直接忽略, 原因未知
            return False
        except Exception as e:
            print(e)
            return False

        self.request_line = request_line.decode()
        try:
            self.parse_request_line(self.request_line)
        except ValueError as e:
            self.send_error(HTTPStatus.BAD_REQUEST, message=str(e))
            return False
        self.parse_headers(raw_headers.decode())

        if "content-length" in self.request_headers:
            content_length = int(self.request_headers["content-length"])
            if len(raw_body) < content_length:
                to_read = content_length - len(raw_body)
                raw_body += self.client_socket.recv(to_read if to_read < SIZE else SIZE)

        if self.aes:
            raw_body = self.aes.decrypt(raw_body)
        raw_body = raw_body.decode()
        self.request_body = raw_body

        self.log_debug(f"request line:\n{self.request_line}")
        self.log_debug(f"request headers:\n{self.request_headers}")
        self.log_debug(f"request body:\n{self.request_body}")

        authorized_pass = False
        if self.verify_cookie():
            self.log_debug(f"cookie verified: {self.user.username}")
            authorized_pass = True
        elif self.authorize():
            self.log_debug(f"authorization verified: {self.user.username}")
            authorized_pass = True
            self.set_cookie()

        if authorized_pass:
            method_name = "do_" + self.request_method
            if hasattr(self, method_name):
                method = getattr(self, method_name)
                method()
            else:
                self.send_error(HTTPStatus.NOT_IMPLEMENTED)
        if self.request_headers.get("connection").lower() == "keep-alive":
            self.log_message("Connection: keep-alive")
            return True
        elif self.request_headers.get("connection").lower() == "close":
            self.log_message("Connection: close")
            return False
        else:
            self.log_message("No 'Connection' header found, closing connection")
            return False

    def parse_request_line(self, request_line):
        method, url, version = request_line.split(" ")
        self.request_url = url
        self.request_method = method
        self.request_httpVersion = version
        path, query = url.split("?") if "?" in url else (url, None)
        if not path.startswith("/"):
            raise ValueError(f"Malformed path: {path}")
        self.request_path = path
        for param in query.split("&") if query else []:
            if "=" not in param:
                raise ValueError(f"Malformed parameter: {param}")
            key, value = param.split("=")
            self.request_params[key] = value

    def parse_headers(self, raw_headers):
        for line in raw_headers.split("\r\n"):
            key, value = line.split(":", 1)
            self.request_headers[key.lower()] = value.strip()

    def send_response(self, code, message=None):
        self.log_request(code)
        response_line = f"HTTP/1.1 {code} {message}\r\n"
        self.response_headers = [
            response_line.encode("latin-1", "strict")
        ] + self.response_headers
        self.send_header("Server", "CS305-2023Fall-PROJ-MiniHttpServer HTTP/1.1")
        self.send_header("Date", self.date_time_string())

    def send_error(self, code: HTTPStatus, headers=None, message=None):
        self.log_error(
            "code %d, message: %s", code, message if message else code.description
        )
        self.send_response(code, code.phrase)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key, value in headers.items() if headers else []:
            self.send_header(key, value)
        response_body = f"""
                    <html>
                        <head><title>Error {code}</title></head>
                        <body>
                            <h1>Error {code}</h1>
                            <p>{code.phrase} {code.description}</p>
                            <p>{message}</p> 
                        </body>
                    </html>
                        """.encode()
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.client_socket.sendall(response_body)

    def send_header(self, key, value):
        header_line = f"{key}: {value}\r\n"
        self.response_headers.append(header_line.encode("latin-1", "strict"))

    def end_headers(self):
        self.response_headers.append(b"\r\n")
        self.client_socket.sendall(b"".join(self.response_headers))
        self.response_headers = []

    def send_body(self, body):
        self.client_socket.sendall(body)

    def log_request(self, code="-"):
        if isinstance(code, HTTPStatus):
            code = code.value
        print(
            f'\033[94mLOG {self.client_address} [{self.log_date_time_string()}] "{self.request_line}" {str(code)}\033[0m'
        )

    def log_error(self, format, *args):
        print(
            f"\033[91mERR {self.client_address} [{self.log_date_time_string()}] {format % args}\033[0m"
        )

    def log_message(self, format, *args):
        print(
            f"\033[92mMSG {self.client_address} [{self.log_date_time_string()}] {format % args}\033[0m"
        )

    def log_debug(self, format, *args):
        if DEBUG:
            print(
                f"\033[93mDBG {self.client_address} [{self.log_date_time_string()}] {format % args}\033[0m"
            )

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        time_tuple = time.localtime(timestamp)
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S", time_tuple)
        return date_str

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
            day,
            self.monthname[month],
            year,
            hh,
            mm,
            ss,
        )
        return s

    weekdayname = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    monthname = [
        None,
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]

    def verify_cookie(self) -> bool:
        if "cookie" not in self.request_headers:
            return False
        cookie = self.request_headers["cookie"].lower()
        if not (cookie.startswith("session-id=") or cookie.startswith("session_id=")):
            return False
        cookie = cookie[11:]
        for user in Users:
            if user.tocken != cookie:  # tocken不匹配
                continue
            if user.tocken_expire_time < int(time.time()):  # tocken过期
                user.tocken = ""
                user.tocken_expire_time = 0
                return False
            self.user = user
            self.user.tocken_expire_time = int(time.time()) + TOCKEN_EXPIRE_TIME
            return True
        return False

    def set_cookie(self):
        if (
            not self.user.tocken
            or self.user.tocken == ""
            or self.user.tocken_expire_time < int(time.time())
        ):
            session_id = secrets.token_hex(16)
            self.log_debug(f"set cookie: {session_id} for user {self.user.username}")
        else:
            session_id = self.user.tocken
        self.user.tocken = session_id
        self.user.tocken_expire_time = int(time.time()) + TOCKEN_EXPIRE_TIME
        self.send_header(
            "Set-Cookie",
            f"session-id={session_id}; Max-Age={TOCKEN_EXPIRE_TIME}; Path=/",
        )

    def authorize(self) -> bool:
        if "authorization" not in self.request_headers:
            self.send_error(
                HTTPStatus.UNAUTHORIZED,
                headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
            )
            return False
        authorization = self.request_headers["authorization"]
        if not authorization.startswith("Basic "):
            self.send_error(
                HTTPStatus.UNAUTHORIZED,
                headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
                message="Invalid authorization type",
            )
            return False
        try:
            authorization = base64.b64decode(authorization[6:]).decode()
            username, password = authorization.split(":")
        except Exception:
            self.send_error(
                HTTPStatus.UNAUTHORIZED,
                headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
                message="Invalid authorization format",
            )
            return False
        for user in Users:
            if user.username == username and user.password == password:
                self.user = user
                return True
        self.send_error(
            HTTPStatus.UNAUTHORIZED,
            headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
            message="Invalid username or password",
        )
        return False


# 定义HTTP请求处理类
class HttpRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, client_socket, client_address):
        super().__init__(client_socket, client_address)
        self.fileSystem = FileSystem(ROOT)

    def do_GET(self, NOT_SEND_BODY=False):
        """Serve a GET request."""
        if self.request_url.startswith("/favicon.ico"):
            size, mimetype, content = self.fileSystem.get_file("/asserts/favicon.ico")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mimetype)
            self.send_header("Content-Length", size)
            self.end_headers()
            self.send_body(content)
            return
        if self.request_url.startswith("/upload") or self.request_url.startswith(
            "/delete"
        ):
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return

        request_path = self.request_path

        # 检查文件是否存在
        if not self.fileSystem.exists(request_path):
            self.send_error(HTTPStatus.NOT_FOUND, message="File or directory not found")
            return

        # 检查是否是目录
        if self.fileSystem.is_dir(request_path):
            # 目录
            # 目录存在，但是没有以/结尾，重定向到以/结尾的url
            # if not request_path.endswith("/"):
            # self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            # location = self.request_path + "/"
            # if self.request_params:
            #     location += "?" + "&".join(
            #         [f"{key}={value}" for key, value in self.request_params.items()]
            #     )
            # self.send_header("Location", location)
            # self.end_headers()
            # return
            try:
                if (
                    "SUSTech-HTTP" not in self.request_params
                    or self.request_params["SUSTech-HTTP"] == "0"
                ):
                    # SUSTech-HTTP字段为0, 返回 html
                    dir_list = self.fileSystem.list_directory(request_path)
                    if not self.fileSystem.is_same_path(request_path, f"/"):
                        dir_list = ["../"] + dir_list
                    dir_list = [
                        f'<li><a href="{os.path.join(self.request_path, item)}?SUSTech-HTTP=0">{item}</a></li>'
                        if item.endswith("/")
                        else f'<li><a href="{os.path.join(self.request_path, item)}?SUSTech-HTTP=1">{item}</a></li>'
                        for item in dir_list
                    ]
                    dir_list = [f'<li><a href="/?SUSTech-HTTP=0">/</a></li>'] + dir_list
                    dir_list = "\n            ".join(dir_list)
                    dir_list = f"""<html>
                                            <head><title>Index of {self.request_path}</title></head>
                                            <body>
                                                <h1>Index of {self.request_path}</h1>
                                                <ul>
                                                    {dir_list}
                                                </ul>
                                            </body>
                                        </html>
                                        """.encode()
                elif self.request_params["SUSTech-HTTP"] == "1":
                    # SUSTech-HTTP字段为1, 返回列表
                    dir_list = str(
                        self.fileSystem.list_directory(request_path)
                    ).encode()
                else:
                    # SUSTech-HTTP字段不为0或1
                    self.send_error(
                        HTTPStatus.BAD_REQUEST,
                        message='Invalid header "SUSTech-HTTP"',
                    )
                    return
                dir_list = self.aes.encrypt(dir_list) if self.aes else dir_list
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(dir_list)))
                self.end_headers()
                if NOT_SEND_BODY is False:
                    self.send_body(dir_list)
            except Exception as e:
                print(e)
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        elif self.fileSystem.is_file(request_path):
            # 如果是文件，则读取文件内容并发送
            try:
                if "range" in self.request_headers:
                    self.get_file_breakpoint_transmission(request_path, NOT_SEND_BODY)
                elif (
                    "chunked" in self.request_params
                    and self.request_params["chunked"] == "1"
                ):
                    self.get_file_chunked(request_path, NOT_SEND_BODY)
                else:
                    self.get_file_raw(request_path, NOT_SEND_BODY)
            except IOError:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_HEAD(self):
        """Serve a HEAD request."""
        if self.request_path == "/" or self.request_path == "":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", str(0))
            self.end_headers()
        else:
            self.do_GET(NOT_SEND_BODY=True)

    def do_POST(self):
        """Serve a POST request"""
        if self.request_path != "/upload" and self.request_path != "/delete":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        if "path" not in self.request_params:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if not self.request_params["path"].startswith("/"):
            self.request_params["path"] = "/" + self.request_params["path"]
        if not self.request_params["path"].startswith(f"/{self.user.username}"):
            self.send_error(
                HTTPStatus.FORBIDDEN,
                message="You can only access your own files",
            )
            return
        if not self.fileSystem.is_dir(f"/{self.user.username}"):
            os.makedirs(f"{ROOT}/{self.user.username}", exist_ok=True)

        if self.request_path == "/upload":
            try:
                boundary = self.extract_boundary(self.request_headers["content-type"])
                for filename, content in self.parse_multipart(
                    self.request_body, boundary
                ):
                    filepath = os.path.join(
                        self.request_params["path"], filename.lstrip("/")
                    )
                    self.fileSystem.save_file(filepath, content)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(0))
                self.end_headers()
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

        elif self.request_path == "/delete":
            try:
                self.fileSystem.delete_dir_or_file(self.request_params["path"])
                os.makedirs(f"{ROOT}/{self.user.username}", exist_ok=True)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(0))
                self.end_headers()
            except FileNotFoundError:
                self.send_error(
                    HTTPStatus.NOT_FOUND, message="File or directory not exists"
                )
            except Exception:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def extract_boundary(self, content_type):
        # 检查是否为multipart/form-data
        if "multipart/form-data" not in content_type:
            raise ValueError("Invalid content-type: %s" % content_type)

        # 分割头部以获取各个部分
        parts = content_type.split(";")
        # 遍历部分以查找boundary
        for part in parts:
            if "boundary=" in part:
                # 去除可能的空格，然后分割以获取boundary值
                boundary = part.strip().split("=")[1]
                return boundary
        raise ValueError("Invalid content-type: missing boundary")

    def parse_multipart(self, body, boundary):
        # 将边界标识符添加到前后，以正确分割数据
        boundary = "--" + boundary

        # 分割原始请求体
        parts = body.split(boundary)

        for part in parts:
            if "Content-Disposition" in part:
                # 分割头部和数据
                headers, content = part.split("\r\n\r\n", 1)
                headers = headers.strip()
                content = content.rstrip("\r\n")

                # 提取Content-Disposition头部
                disposition = [
                    h
                    for h in headers.split("\r\n")
                    if h.startswith("Content-Disposition")
                ][0]

                # 提取文件名（如果存在）
                if "filename=" in disposition:
                    filename = disposition.split("filename=")[1].strip('"')
                else:
                    filename = None

                yield filename, content

    def get_file_raw(self, request_path, NOT_SEND_BODY):
        size, mimetype, content = self.fileSystem.get_file(request_path)
        content = self.aes.encrypt(content) if self.aes else content
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", mimetype)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        if NOT_SEND_BODY is False:
            self.send_body(content)

    def get_file_chunked(self, request_path, NOT_SEND_BODY):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", self.fileSystem.get_file_type(request_path))
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        if NOT_SEND_BODY is False:
            for content in self.fileSystem.get_file_chunks(
                request_path, chunk_size=CHUNK_SIZE
            ):
                content = self.aes.encrypt(content) if self.aes else content
                self.send_body(b"%X\r\n%s\r\n" % (len(content), content))
            self.send_body(b"0\r\n\r\n")

    def get_file_breakpoint_transmission(self, request_path, NOT_SEND_BODY):
        try:
            content_size = self.fileSystem.get_file_size(request_path)
            ranges = self.parse_ranges(self.request_headers["range"], content_size)
            self.log_debug(f"ranges: {ranges}")
            # 不进行merge, 直接返回多个部分
            # if self.validate_ranges(ranges, content_size):
            #     ranges = self.merge_ranges(ranges)
            # else:
            #     raise ValueError("Invalid range for file size")
            # self.log_debug(f"merged ranges: {ranges}")
            if not self.validate_ranges(ranges, content_size):
                raise ValueError("Invalid range for file size")
            contents = []
            for range_ in ranges:
                contents.append(
                    self.fileSystem.get_file_part(request_path, range_[0], range_[1])
                )
        except ValueError as e:
            self.send_error(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                message=str(e),
            )

        self.send_response(HTTPStatus.PARTIAL_CONTENT)

        if len(contents) == 1:
            content = contents[0]
            content = self.aes.encrypt(content) if self.aes else content
            self.send_header(
                "Content-Type", self.fileSystem.get_file_type(request_path)
            )
            self.send_header("Content-length", str(len(content)))
            self.send_header(
                "Content-range",
                f"bytes {ranges[0][0]}-{ranges[0][1]}/{content_size}",
            )
            self.end_headers()
            if NOT_SEND_BODY is False:
                self.send_body(content)
        else:
            boundary = secrets.token_hex(16)
            self.send_header(
                "Content-Type", f"multipart/byteranges; boundary={boundary}"
            )
            entity_body = b""
            for range_, content in zip(ranges, contents):
                entity_body += (
                    f"--{boundary}\r\n"
                    f"Content-type: {self.fileSystem.get_file_type(request_path)}\r\n"
                    f"Content-range: bytes {range_[0]}-{range_[1]}/{content_size}\r\n"
                    f"\r\n"
                ).encode()
                entity_body += self.aes.encrypt(content) if self.aes else content
                entity_body += b"\r\n"
            entity_body += f"--{boundary}--\r\n".encode()

            self.send_header("Content-length", str(len(entity_body)))
            self.end_headers()
            if NOT_SEND_BODY is False:
                self.send_body(entity_body)

    def parse_ranges(self, range_header, content_size):
        # 移除 "bytes=" 前缀并按逗号分割
        ranges = range_header.replace("bytes=", "").split(",")
        result = []

        for r in ranges:
            start, end = r.split("-")
            end = int(end) if end else None
            if start == "":
                start = content_size - end
                end = content_size - 1
            else:
                start = int(start) if start else None
            result.append((start, end))

        return result

    def validate_ranges(self, ranges, content_size):
        return all(
            start <= end and end <= content_size
            for start, end in ranges
            if start is not None and end is not None
        )

    def merge_ranges(self, ranges):
        ranges.sort()
        merged = []

        for current in ranges:
            if not merged or current[0] > merged[-1][1] + 1:
                merged.append(current)
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], current[1]))

        return merged


class FileSystem:
    def __init__(self, root):
        self.root = root

    def is_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        return os.path.isfile(filepath)

    def is_dir(self, path):
        dirpath = os.path.join(self.root, path.lstrip("/"))
        return os.path.isdir(dirpath)

    def exists(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        return os.path.exists(filepath)

    def is_same_path(self, path1, path2):
        filepath1 = os.path.join(self.root, path1.lstrip("/"))
        filepath2 = os.path.join(self.root, path2.lstrip("/"))
        return os.path.samefile(filepath1, filepath2)

    def get_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        size = os.path.getsize(filepath)
        mimetype = mimetypes.guess_type(filepath)[0]
        with open(filepath, "rb") as file:
            content = file.read()
        return size, mimetype, content

    def get_file_type(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        return mimetypes.guess_type(filepath)[0]

    def get_file_size(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        return os.path.getsize(filepath)

    def get_file_chunks(self, path, chunk_size=1024):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        with open(filepath, "rb") as file:
            while True:
                content = file.read(chunk_size)
                if not content:
                    break
                yield content

    def get_file_part(self, path, start, end):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError("File does not exist")

        if start < 0 or end > os.path.getsize(filepath):
            raise ValueError("Invalid range for file size")

        with open(filepath, "rb") as file:
            file.seek(start)  # 移动到开始位置
            return file.read(end - start + 1)  # 读取指定范围的数据

    def save_file(self, path, content):
        filepath = os.path.join(self.root, path.lstrip("/"))
        directory = os.path.dirname(filepath)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        with open(filepath, "wb") as file:
            file.write(content.encode())

    def delete_dir_or_file(self, path):
        path = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(path):
            raise FileNotFoundError
        if os.path.isdir(path):
            # 遍历目录
            for root, dirs, files in os.walk(path, topdown=False):
                # 删除所有文件
                for file in files:
                    os.remove(os.path.join(root, file))
                # 删除所有子目录
                for dir in dirs:
                    os.rmdir(os.path.join(root, dir))

            # 删除目录本身
            os.rmdir(path)
        else:
            os.remove(path)

    def delete_directory(self, path):
        dirpath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(dirpath):
            raise FileNotFoundError
        if not os.path.isdir(dirpath):
            raise NotADirectoryError
        os.rmdir(dirpath)
        os.makedirs(dirpath, exist_ok=True)

    def delete_file(self, path):
        filepath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(filepath):
            raise FileNotFoundError
        if not os.path.isfile(filepath):
            raise IsADirectoryError
        os.remove(filepath)

    def list_directory(self, path):
        dirpath = os.path.join(self.root, path.lstrip("/"))
        if not os.path.exists(dirpath):
            raise FileNotFoundError
        if not os.path.isdir(dirpath):
            raise NotADirectoryError
        dir_list = os.listdir(dirpath)
        for i in range(len(dir_list)):
            if os.path.isdir(os.path.join(dirpath, dir_list[i])):
                dir_list[i] += "/"
        return dir_list


class RSA:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, message):
        encrypted_message = self.public_key.encrypt(
            message,
            pd_rsa.OAEP(
                mgf=pd_rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted_message

    def decrypt(self, message):
        decrypted_message = self.private_key.decrypt(
            message,
            pd_rsa.OAEP(
                mgf=pd_rsa.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_message


class AES:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.cipher = Cipher(
            algorithms.AES(key), modes.CBC(iv), backend=default_backend()
        )

    def encrypt(self, message):
        padder = pd_aes.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        encryptor = self.cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_message

    def decrypt(self, message):
        if message is None or message == b"":
            return message
        decryptor = self.cipher.decryptor()
        decrypted_data = decryptor.update(message) + decryptor.finalize()
        unpadder = pd_aes.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data


class EncryptorServer:
    def __init__(self, connection):
        self.connection = connection
        self.rsa = RSA(PUBLIC_KEY, PRIVATE_KEY)
        self.aes = None
        self.hello()

    def hello(self):
        self.connection.sendall(
            PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def handle_request(self):
        request = self.connection.recv(2048)
        request = self.rsa.decrypt(request)
        print(request)
        key, iv = request.split(b"\r\n")
        self.aes = AES(key, iv)
        self.connection.sendall(b"OK")
        return self.aes


socket_list = []
lock = threading.Lock()


# 处理每个客户端连接
def handle_client(connection, address):
    try:
        httpRequestHandler = HttpRequestHandler(
            client_socket=connection,
            client_address=address,
        )
        while httpRequestHandler.handle_request():
            httpRequestHandler.user = None

            httpRequestHandler.request_line = None
            httpRequestHandler.request_method = None
            httpRequestHandler.request_url = None
            httpRequestHandler.request_path = None
            httpRequestHandler.request_params = {}
            httpRequestHandler.request_httpVersion = None
            httpRequestHandler.request_headers = {}
            httpRequestHandler.request_body = None

            httpRequestHandler.response_headers = []
    finally:
        with lock:
            connection.close()
            socket_list.remove(connection)
            print(f"socket {address} is closed")


# 运行服务器
def run_server(host, port):
    server_address = (host, port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen()
        server_socket.settimeout(1)  # 设置超时时间

        print(f"HTTP Server running on {host}:{port}")

        while True:
            try:
                connection, address = server_socket.accept()
                thread = threading.Thread(
                    target=handle_client, args=(connection, address)
                )
                socket_list.append(connection)
                thread.start()
            except socket.timeout:
                pass


# 信号处理函数
def signal_handler(signum, frame):
    print("Interrupt received, shutting down the server")
    # 这里可以添加任何清理代码
    with lock:
        for s in socket_list:
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception:
                ...
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Server")
    parser.add_argument(
        "-i",
        "--host",
        type=str,
        default="localhost",
        help="Host address",
    )
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port number")

    args = parser.parse_args()

    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    run_server(args.host, args.port)