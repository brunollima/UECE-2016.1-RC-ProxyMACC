# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
import datetime
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser

def log(type, service, attrs):

    #print(attrs)
    
    if (type == 'w'):
        logType = "Warning"
        file = "log"
        color = 35
    elif(type == 'e'):
        logType = "Error"
        file = "error"
        color = 31
    else:
        logType = "Information"
        file = "log"
        color = 0
    
    print "\x1b[%dm%s: %s\x1b[0m" % (color, service, attrs)

    filename = open('log/%s' % file, 'a')
    if(service == "REQUEST"):
    	text = "[{0}] [{1}] [{2}] [{3}] [{4}] [{5}] [{6}] {7}\n".format(datetime.datetime.now(), logType, service, attrs['from_addr'], attrs['to_addr'], attrs['command'], attrs['user_agent'], attrs['text'])
        filename.write(text)
    elif(service == "RESPONSE"):
        text = "[{0}] [{1}] [{2}] [{3}] [{4}] [{5}] [{6}] [{7}] {8}\n".format(str(datetime.datetime.now()), logType, service, attrs['server_path'], attrs['client_address'], attrs['method'], attrs['status'], attrs['response_version'], attrs['text'])
        filename.write(text)
    else:
    	text = "[{0}] [{1}] [{2}] {3}\n".format(str(datetime.datetime.now()), logType, service, attrs['text'])
        filename.write(text)
        pass
    filename.close()

def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return
        self.log_message(format, *args)

    def do_GET(self):
        if self.path == 'http://proxy.macc/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        req_headers = self.filter_headers(req.headers)

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            err[text] = 'Tempo esgotado. Código 502'
            log('e', '', err)
            return

        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        setattr(res, 'headers', res.msg)
        setattr(res, 'response_version', version_table[res.version])

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_headers = self.filter_headers(res.headers)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        self.save_handler(req, req_body, res, res_body_plain)

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        return headers

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def save_handler(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        #destination = req.path
        #client = req.client_address[0]
        #print with_color(32, type(client))
        #print req.__dict__.keys()

        req_attrs = {'from_addr' : str(req.client_address[0]), 'to_addr' : str(req.path), 'command' : str(req.command), 'user_agent' : str(req.headers.get('User-Agent', '')), 'text' : "NULL"}
        #print req_attrs
        log('i', 'REQUEST', req_attrs)

        #print (res.__dict__.keys())

        #print res.response_version
        #print res.headers

        res_attrs = {'method' : res._method, 'status' : res.status, 'response_version' : res.response_version, 'client_address' : req.client_address[0], 'server_path' : req.path, 'text' : 'NULL'}
        #print res_attrs
        log('i', 'RESPONSE', res_attrs)


if __name__ == '__main__':
    port = 3128
    server_address = ('', port)

    ProxyRequestHandler.protocol_version = "HTTP/1.1"
    httpd = ThreadingHTTPServer(server_address, ProxyRequestHandler)

    socket_address = httpd.socket.getsockname()
    t = {}
    t['text'] = "Proxy Inicializado em %s, porta %s" % (socket_address[0], socket_address[1])
    log('i', 'INIT', t)
    httpd.serve_forever()
