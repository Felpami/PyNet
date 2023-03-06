import socket
import os
import threading
import magic
import base64
import json
import re
from datetime import datetime
from colorama import Fore, Back
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class PyNet_session:
    def __init__(self, secret, name='PyNetSESSION'):
        self.secret = pad(secret.encode(), 32)
        self.name = name

    def enc(self, value):
        try:
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.secret, AES.MODE_CBC, iv)
            return (base64.b64encode(cipher.encrypt(pad(value.encode(), AES.block_size))) + b'.' + base64.b64encode(
                iv)).decode()
        except Exception:
            return None

    def dec(self, value):
        try:
            enc, iv = value.split('.')
            enc = base64.b64decode(enc)
            iv = base64.b64decode(iv)
            cipher = AES.new(self.secret, AES.MODE_CBC, iv)
            return json.loads(unpad(cipher.decrypt(enc), AES.block_size).decode())
        except Exception:
            return None


class PyNet_template:
    def __init__(self):
        pass

    def template(self, file, **args):
        with open(os.path.abspath(f'template/{file}'), 'r') as reader:
            content = reader.read()
        match_expression = re.findall(r'<!!([\S\s]*?)!!>', content)
        for match in match_expression:
            try:
                eval_expression = str(eval(match, args))
            except Exception:
                eval_expression = ''
            content = content.replace(f'<!!{match}!!>', eval_expression)
        match_condition = re.findall(r'(<\?\?\s*[\S\s]*?\s*\?\?>)', content)
        if match_condition:
            check = [[True, True, False]]
            count = 0
            new_content = content
            for index, condition_all in enumerate(match_condition):
                condition = re.findall(r'<\?\?\s*([\S\s]*?)\s*\?\?>', content)
                if len(match_condition) - 1 != index:
                    condition_escaped = re.sub(r'[^a-zA-Z0-9 ]', r'\\\g<0>', match_condition[index])
                    condition_escaped_next = re.sub(r'[^a-zA-Z0-9 ]', r'\\\g<0>', match_condition[index + 1])
                    condition_content = re.findall(f'{condition_escaped}([\s\S]*?){condition_escaped_next}',
                                                   content)[0]
                else:
                    condition_content = ''
                if count >= 0:
                    verb, expression = re.findall(r'^(\w*)\s*\(?([^()]*)\)?', condition[index])[0]
                    if len(check) == 1 and verb != 'if':
                        raise Exception(f'{file} template syntax has some errors.')
                    if verb == 'if':
                        if check[count][1]:
                            try:
                                res = eval(expression, args)
                            except Exception as e:
                                print(e)
                                res = False
                            if res:
                                check.append([True, True, False])
                                new_content = new_content.replace(condition_all + condition_content, condition_content,
                                                                  1)
                            else:
                                check.append([True, False, False])
                                new_content = new_content.replace(condition_all + condition_content, '', 1)
                        else:
                            check.append([True, None, False])
                            new_content = new_content.replace(condition_all + condition_content, '', 1)
                        count += 1
                    elif verb == 'elif':
                        if not check[count][1]:
                            try:
                                res = eval(expression, args)
                            except Exception:
                                res = False
                            if res:
                                check[count][2] = True
                                new_content = new_content.replace(condition_all + condition_content, condition_content,
                                                                  1)
                            else:
                                check[count][2] = False
                                new_content = new_content.replace(condition_all + condition_content, '', 1)
                        else:
                            new_content = new_content.replace(condition_all + condition_content, '', 1)
                    elif verb == 'else':
                        if not check[count][1] and not check[count][2]:
                            new_content = new_content.replace(condition_all + condition_content, condition_content, 1)
                        else:
                            new_content = new_content.replace(condition_all + condition_content, '', 1)
                    elif verb == 'endif' and check[count][0]:
                        check.pop()
                        count -= 1
                        new_content = new_content.replace(condition_all + condition_content, '', 1)
                    else:
                        raise Exception(f'{file} template syntax has some errors.')
            if len(check) != 1:
                raise Exception(f'{file} template syntax has some errors.')
            else:
                return new_content


class PyNet:
    def __init__(self, port=8080, address="127.0.0.1"):
        self.port = port
        self.address = address
        self.endpoint_defined = {}
        self.endpoint_dict = {}
        self.sock = None
        self.session_manager = None

    def handle_request(self, addr, req):
        self.list_file_in_static()
        request = self.Requester(self, req, addr, self.endpoint_dict)
        response = self.Responder(self, request.verb, request.protocol)
        if request.exit_code:
            response.set_code(request.exit_code)
            resp = response.return_response()
            del request
            del response
            return resp
        else:
            response.allowed_methods = self.endpoint_dict[request.endpoint].allowed_methods
            resp_exec = self.endpoint_dict[request.endpoint].exec_function(request, response)
            del request
            del response
            return resp_exec

    def list_file_in_static(self):
        def iterate(directory=''):
            self.endpoint_dict = {}
            file_array = os.listdir(os.path.abspath(f'static/{directory}'))
            for file in file_array:
                if os.path.isfile(os.path.abspath(f'static/{directory}{file}')):
                    def file_200(request, response, arg):
                        with open(os.path.abspath(f'static/{directory}{arg}'), 'rb') as reader:
                            content = reader.read()
                            response.set_header('Content-Type', magic.from_file(os.path.abspath(f'static/{directory}{arg}'), mime=True))
                            return content
                    self.endpoint_dict[f'/{directory}{file}'] = self.Endpoint(self, f'/{directory}{file}', ['GET'], file_200, file)
                else:
                    def directory_302(request, response, arg):
                        response.set_code(302)
                        response.set_header('Location', f'{arg}/')
                        return ''
                    def directory_403(request, response):
                        response.set_code(403)
                        return ''
                    self.endpoint_dict[f'/{directory}{file}'] = self.Endpoint(self, f'/{directory}{file}', ['GET'], directory_302, file)
                    self.endpoint_dict[f'/{directory}{file}/'] = self.Endpoint(self, f'/{directory}{file}/', ['GET'], directory_403)
                    iterate(f'{directory}{file}/')
        iterate()
        self.endpoint_dict = self.endpoint_defined | self.endpoint_dict

    def add_endpoint(self, route, allowed_methods=None):
        if allowed_methods is None:
            allowed_methods = ['GET']

        def set_func(endpoint_function):
            self.endpoint_defined[route] = self.Endpoint(self, route, allowed_methods, endpoint_function)
        return set_func

    def serve(self):
        if self.session_manager is None:
            self.server_warning(f'Using deafult session manager.')
            self.session_manager = PyNet_session('SECRET')
            self.server_warning(f'Consider creating a custom session manager -> PyNet_session("{{KEY}}")')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock = sock
        sock.bind((self.address, self.port))
        self.server_success(f'Server started on {self.address}:{self.port}')
        sock.listen()
        while True:
            try:
                conn, addr = sock.accept()
            except socket.error as e:
                print(e)
                self.server_error(f'Error serving request.')
            else:
                try:
                    threading.Thread(target=self.run_thread, args=(conn, addr,), daemon=True).start()
                except KeyboardInterrupt:
                    sock.close()
                    self.server_success(f'Quitting server! (~^w^)~')

    def run_thread(self, conn, addr):
        with conn:
            req = b''
            while True:
                temp = conn.recv(1024)
                req += temp
                if len(temp) < 1024:
                    break
            resp = self.handle_request(addr, req)
            self.server_success_send(f'Sending response to {addr}')
            conn.sendall(resp)

    def get_time(self):
        return f'[{datetime.strftime(datetime.now(), "%H:%M:%S:%f")}]'

    def server_success_send(self, text):
        print('[' + Fore.CYAN + '+' + Fore.RESET + f'] {self.get_time()} {self.get_time()} {text}')

    def server_success(self, text):
        print('[' + Fore.GREEN + '+' + Fore.RESET + f'] {self.get_time()} {text}')

    def server_warning(self, text):
        print('[' + Fore.YELLOW + '*' + Fore.RESET + f'] {self.get_time()} {text}')

    def server_error(self, text):
        print('[' + Fore.RED + '-' + Fore.RESET + f'] {self.get_time()} {text}')

    class Endpoint:
        def __init__(self, pynet, url, allowed_methods, calling_func, arg=None):
            self.url = url
            self.pynet = pynet
            self.allowed_methods = set(allowed_methods)
            self.allowed_methods.add('OPTIONS')
            self.calling_func = calling_func
            self.argument = arg

        def exec_function(self, request, response):
            try:
                if self.argument is not None:
                    resp_exec = self.calling_func(request, response, self.argument)
                else:
                    resp_exec = self.calling_func(request, response)
                if isinstance(resp_exec, tuple):
                    body = resp_exec[0]
                    code = (resp_exec[1])
                else:
                    body = resp_exec
                    code = response.code
                if isinstance(body, str):
                    body = body.encode('latin-1')
                response.set_header('Content-Type', magic.from_buffer(body, mime=True))
                response.body = body
                response.set_code(code)
                return response.return_response()
            except Exception as e:
                PyNet.server_error(self.pynet, f'Internal server error: {e}')
                response.set_code(500)
                return response.return_response()

    class Responder:
        def __init__(self, pynet, verb, protocol):
            self.body = b''
            self.pynet = pynet
            self.headers = {'Server': 'FelpaServer\\v.0.1'}
            self.headers_string = ''
            self.code_dict = {200: 'OK', 300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Found',
                              304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
                              400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
                              405: 'Method Not Allowed', 500: 'Internal Server Error'}
            self.allowed_methods = ['GET', 'OPTIONS']
            self.code = 200
            self.verb = verb
            self.session = {}
            self.protocol = self.set_protocol(protocol)
            self.concatenate_header()

        def set_protocol(self, protocol):
            if protocol is None:
                return 'HTTP/1.1'
            else:
                return protocol

        def return_response(self):
            top = f'{self.protocol} {self.code} {self.code_dict[self.code]}\r\n'
            if self.verb == 'HEAD':
                self.body = b''
            elif self.verb == 'OPTIONS':
                self.set_header('Allow', ','.join(self.allowed_methods))
                self.body = b''
            if len(self.session):
                #self.set_header('Set-Cookie', self.pynet.session_manager.name+'='+self.pynet.session_manager.enc((str(self.session)).replace('\'', '"')))
                enc_cookie = self.pynet.session_manager.enc((str(self.session)).replace('\'', '"'))
                if enc_cookie:
                    self.set_cookie(self.pynet.session_manager.name, enc_cookie , http_only=True)
            self.set_header('Content-Length', f'{len(self.body)}')
            self.concatenate_header()
            return top.encode("latin-1")+self.headers_string.encode("latin-1")+b'\r\n'+self.body

        def concatenate_header(self, key=None, value=None):
            if key and value:
                self.headers_string += f'{key}: {value}\r\n'
            else:
                for key in self.headers:
                    self.headers_string += f'{key}: {self.headers[key]}\r\n'
                    #print(self.headers_string)
                self.headers = {}

        def set_code(self, code):
            self.code = code

        def set_header(self, key, value):
            self.headers[key] = value

        def set_cookie(self, key, value, secure=False, http_only=False, samesite=None, path='/', domain=None, expires=None):
            add = ''
            if secure:
                add += 'Secure; '
            if http_only:
                add += 'HttpOnly; '
            add += f'Path={path}; '
            if samesite:
                add += f'Samsite={samesite}; '
            if domain:
                add += f'Domain={domain}; '
            if expires:
                add += f'Expires={expires}'
            else:
                add = add[:-2]
            self.concatenate_header('Set-Cookie', f'{key}={value}; {add}')

        def remove_header(self, key):
            self.headers.pop(key, None)

    class Requester:
        def __init__(self, pynet, req, addr, endpoint_dict):
            self.request = req
            self.pynet = pynet
            self.addr = addr
            self.endpoint_dict = endpoint_dict
            self.endpoint = ''
            self.query_string = []
            self.get = {}
            self.post = {}
            self.file = {}
            self.cookie = {}
            self.verb = None
            self.protocol = None
            self.request_headers = {}
            self.session = {}
            self.exit_code = self.handle()

        def request_headers_convert(self, array):
            for el in array:
                try:
                    key, value = el.split(':',1)
                    self.request_headers[key] = value
                except Exception:
                    pass

        def parser(self):
            header_lookfor = ['Content-Type']
            top, *body = list(filter(None, self.request.decode().split('\r\n\r\n', 1)))
            try:
                self.verb, url, self.protocol = re.findall(r'^([A-Z]*)[^\S\r\n]*(\/\S*)[^\S\r\n]*(HTTP\/[0-9]\.[0-9])', top.split('\r\n')[0])[0]
            except Exception:
                return 1
            self.endpoint, *query_temp = url.split('?', 1)
            if len(query_temp):
                match = re.findall('([^\r\n\t\f\v &]*?)=([^\r\n\t\f\v &]*?)(?=&|$)', query_temp[0])
                for key, value in match:
                    self.get[key] = value
            match = re.findall(r'(\S*)[^\S\r\n]*:[^\S\r\n]*(.*)', top)
            for key, values in match:
                if key in header_lookfor:
                    match_value = re.findall('[^\n\r\v\f\v ;=]+', values)
                    self.request_headers[key] = match_value
                else:
                    self.request_headers[key] = values
            cookies = self.request_headers.get('Cookie')
            if cookies:
                match = re.findall(r'([^\r\n\t\f\v &]*?)=([^\r\n\t\f\v ]*?)(?= |;|$)', cookies.strip())
                for key, value in match:
                    if key == self.pynet.session_manager.name:
                        dec_cookie = self.pynet.session_manager.dec(value)
                        if dec_cookie:
                            self.session = dec_cookie
                    else:
                        self.cookie[key] = value
            array = self.request_headers.get('Content-Type')
            if array and len(body):
                if array[0] == 'application/x-www-form-urlencoded':
                    match = re.findall('([^\r\n\t\f\v &]*?)=([^\r\n\t\f\v &]*?)(?=&|$)', body[0])
                    for key, value in match:
                        self.post[key] = value
                elif array[0] == 'multipart/form-data':
                    boundary = array[array.index('boundary') + 1]
                    contents = list(filter(None, re.split(f'-{{0,2}}{boundary}-{{0,2}}', body[
                        0].strip())))
                    for content in contents:
                        header_content_dict = {}
                        headers, *cont = list(filter(None, content.split('\r\n\r\n', 1)))
                        match = re.findall(
                            r'([^\r\n\t\f\v &]*?)[^\S\r\n]*[:=][^\S\r\n]*[\'\"]?([^\r\n\t\f\v]*?)(?=\"|\'| |;|$)',
                            headers)
                        for key, value in match:
                            header_content_dict[key.lower()] = value
                        if 'name' in header_content_dict:
                            if 'filename' in header_content_dict:
                                self.file[header_content_dict['name']] = {'filename': header_content_dict['filename'],
                                                                      'content': cont[0].strip()}
                            else:
                                self.post[header_content_dict['name']] = cont[0].strip()
                elif array[0] == 'application/json':
                    try:
                        self.post = json.loads(body[0].strip())
                    except Exception:
                        pass
                elif array[0] == 'application/xml':
                    pass
            return 0

        def handle(self):
            self.exit_code = self.parser()
            if self.endpoint not in self.endpoint_dict:
                return 404
            if self.verb in self.request_headers:
                return 405
            PyNet.server_success(self.pynet,
                                 f'Received request {self.verb} {self.endpoint} {self.protocol} from {self.addr}')
            return self.exit_code
