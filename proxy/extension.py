from mitmproxy import http, ctx
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading
import json
import logging
from urllib.parse import urlparse

class HttpHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        response = self.server.instance.handle_request(post_data)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        return

class HTTPServer(HTTPServer):
    def __init__(self, server_address, handler_class, instance):
        self.instance = instance
        super().__init__(server_address, handler_class)

class MITMInterceptor:
    def __init__(self):
        self.added_header = []
        self.modified_header = []
        self.added_query_param = []
        self.modified_query_param = []
        self.added_body_param = []
        self.modified_body_param = []
        self.intercepted_request = []
        self.intercepted_response = []
        self.history_request = []
        self.history_response = []

        self.server = HTTPServer(('localhost', 5555), HttpHandler, self)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def handle_request(self, data):
        json_data = data.decode("utf-8")
        dict_data = json.loads(json_data)

        operation = dict_data.get("operation")
        name = dict_data.get("name")
        value = dict_data.get("value")
        host = dict_data.get("host")
        path = dict_data.get("path")
        method = dict_data.get("method")
        logging.info(f"operation: {operation}, name: {name}, value: {value}, host: {host}, path: {path}, method: {method}")

        if operation == "add_header":
            self.added_header.append((name, value, host, path, method))
            return {"status": "ok"}
        elif operation == "modify_header":
            self.modified_header.append((name, value, host, path, method))
            return {"status": "ok"}
        elif operation == "add_query_param":
            self.added_query_param.append((name, value, host, path, method))
            return {"status": "ok"}
        elif operation == "modify_query_param":
            self.modified_query_param.append((name, value, host, path, method))
            return {"status": "ok"}
        elif operation == "add_body_param":
            self.added_body_param.append((name, value, host, path, method))
            return {"status": "ok"}
        elif operation == "modify_body_param":
            self.modified_body_param.append((name, value, host, path, method))
            return {"status": "ok"}
        elif operation == "intercept_request":
            self.intercepted_request.append((host, path, method))
            return {"status": "ok"}
        elif operation == "intercept_response":
            self.intercepted_response.append((host, path, method))
            return {"status": "ok"}
        elif operation == "clean":
            self.clean()
            return {"status": "ok"}
        elif operation == "get_history":
            return {"status": "ok", "request": self.history_request, "response": self.history_response}
        else:
            # Unsupported operation
            pass

    def request(self, flow: http.HTTPFlow):
        try:
            self.store_request(flow)    
            
            request = flow.request
            parsed_url = urlparse(request.url)

            host_name = parsed_url.netloc
            request_path = parsed_url.path
            
            headers = request.headers
            query = request.query

            for name, value, condition_host, condition_path, condition_method in self.added_header:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method):
                    headers[name] = value

            for target, value, condition_host, condition_path, condition_method in self.modified_header:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method) and target in headers:
                    headers[target] = value

            for name, value, condition_host, condition_path, condition_method in self.added_query_param:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method):
                    query[name] = value

            for target, value, condition_host, condition_path, condition_method in self.modified_query_param:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method) and target in query:
                    query[target] = value

            content = request.content.decode()
            for name, value, condition_host, condition_path, condition_method  in self.added_body_param:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method):
                    content += "&" + name + "=" + value

            for target, value, condition_host, condition_path, condition_method in self.modified_body_param:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method):
                    content = content.replace(target, value)

            request.content = content.encode()
            url = request.pretty_url

            for condition_host, condition_path, condition_method in self.intercepted_request:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == request_path) and \
                (condition_method is None or condition_method == request.method):
                    flow.kill()

        except Exception as e:
            logging.info(f"Request Error: {e}")
    
    def response(self, flow: http.HTTPFlow):
        try:
            self.store_response(flow)

            response = flow.response

            headers = response.headers
            content = response.get_text()

            parsed_url = urlparse(flow.request.url)
            host_name = parsed_url.netloc
            response_path = parsed_url.path
            
            for condition_host, condition_path, condition_method in self.intercepted_response:
                if (condition_host is None or condition_host == host_name) and \
                (condition_path is None or condition_path == response_path) and \
                (condition_method is None or condition_method == flow.request.method):
                    flow.kill()

        except Exception as e:
            logging.info(f"Response Error: {e}")

    def store_request(self, flow):
        request_data = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "content": flow.request.get_text(),
        }

        self.history_request.append(request_data)
        
    def store_response(self, flow):
        response_data = {
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "content": flow.response.get_text(),
        }

        self.history_response.append(response_data)

    def clean(self):
        self.added_header = []
        self.modified_header = []
        self.added_query_param = []
        self.modified_query_param = []
        self.added_body_param = []
        self.modified_body_param = []
        self.intercepted_request = []
        self.intercepted_response = []
        self.history_request = []
        self.history_response = []

    def done(self):
        try:
            print("Closing server")
            self.server.shutdown()
            self.server_thread.join()
        except Exception as e:
            print("Failed to properly close server: ", e)

addons = [
    MITMInterceptor()
]