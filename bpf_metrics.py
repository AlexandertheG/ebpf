from bcc import BPF
from http.server import SimpleHTTPRequestHandler
import socketserver
import os
import importlib

class MyHttpRequestHandler(SimpleHTTPRequestHandler):

    def do_GET(self):
        prometheus_metrics = ""
        for mdl in module_list:
            prometheus_metrics += mdl.get_metric() + '\n'

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(prometheus_metrics, 'utf-8'))
            
        return

module_list = []
modules_dir = os.curdir + '/modules'
module_py_files = [f for f in os.listdir(modules_dir) if os.path.isfile(modules_dir + '/' + f)]

for f_name in module_py_files:
    mdl_file_name = f_name.split('.')[0]
    module_name = "modules." + mdl_file_name
    name_parts = mdl_file_name.split('_')

    for idx, value in enumerate(name_parts):
        name_parts[idx] = name_parts[idx].capitalize()

    class_name = "".join(name_parts)
    module = importlib.import_module(module_name)
    new_class = getattr(module, class_name)
    new_instance = new_class()
    module_list.append(new_instance)


PORT = 9090
handler_object = MyHttpRequestHandler
my_server = socketserver.TCPServer(("", PORT), handler_object)
my_server.serve_forever()