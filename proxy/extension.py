from mitmproxy import http, ctx
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading
import json
import logging

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
        condition = dict_data.get("condition")
        logging.info(f"{operation}, {name}, {value}, {condition}")

        if operation == "add_header":
            self.added_header.append((name, value))
            return {"status": "ok"}
        elif operation == "modify_header":
            self.modified_header.append((name, value))
            return {"status": "ok"}
        elif operation == "add_query_param":
            self.added_query_param.append((name, value))
            return {"status": "ok"}
        elif operation == "modify_query_param":
            self.modified_query_param.append((name, value))
            return {"status": "ok"}
        elif operation == "add_body_param":
            self.added_body_param.append((name, value))
            return {"status": "ok"}
        elif operation == "modify_body_param":
            self.modified_body_param.append((name, value))
            return {"status": "ok"}
        elif operation == "intercept_request":
            self.intercepted_request.append(condition)
            return {"status": "ok"}
        elif operation == "intercept_response":
            self.intercepted_response.append(condition)
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
            headers = request.headers
            query = request.query

            for name, value in self.added_header:
                headers[name] = value

            for target, value in self.modified_header:
                if target in headers:
                    headers[target] = value

            for name, value in self.added_query_param:
                query[name] = value

            for target, value in self.modified_query_param:
                if target in query:
                    query[target] = value

            content = request.content.decode()
            for name, value in self.added_body_param:
                content += "&" + name + "=" + value

            for target, value in self.modified_body_param:
                content = content.replace(target, value)

            request.content = content.encode()
            url = request.pretty_url

            for condition in self.intercepted_request:
                if condition in url:
                    flow.kill()

                if condition in content:
                    flow.kill()

                for name, value in headers.items():
                    if condition in value:
                        flow.kill()

        except Exception as e:
            logging.info(f"Request Error: {e}")
    
    def response(self, flow: http.HTTPFlow):
        try:
            self.store_response(flow)

            headers = flow.response.headers
            content = flow.response.get_text()

            for condition in self.intercepted_response:
                if condition in content:
                    flow.kill()

                for name, value in headers.items():
                    if condition in value:
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