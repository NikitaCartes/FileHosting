"""Simple HTTP server with upload functionality and optional SSL/TLS support."""

__version__ = '0.3'
__author__ = 'sgrontflix'

import contextlib
import datetime
import email.utils
import http.server
import io
import mimetypes
import os
import posixpath
import re
import socket
import ssl
import sys
import uuid
from base64 import urlsafe_b64encode
from functools import partial
from hashlib import sha3_384
from http import HTTPStatus
from time import time_ns

import database
import storedFile

__db__ = database.Database()


def sanitize_filename(filename: str) -> str:
    """
    Replaces all forbidden chars with '' and removes unnecessary whitespaces
    If, after sanitization, the given filename is empty, the function will return 'file_[UUID][ext]'
    :param filename: filename to be sanitized
    :return: sanitized filename
    """
    chars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|']

    filename = filename.translate({ord(x): '' for x in chars}).strip()
    name = re.sub(r'\.[^.]+$', '', filename)
    extension = re.search(r'(\.[^.]+$)', filename)
    extension = extension.group(1) if extension else ''

    return filename if name else f'file_{uuid.uuid4().hex}{extension}'


class SimpleHTTPRequestHandlerWithUpload(http.server.SimpleHTTPRequestHandler):
    """
    Simple HTTP request handler with upload functionality.
    This class is derived from SimpleHTTPRequestHandler with small tweaks
    to add the upload functionality.
    """

    server_version = 'SimpleHTTPWithUpload/' + __version__

    extensions_map = {
        '': 'application/octet-stream',
        '.manifest': 'text/cache-manifest',
        '.html': 'text/html',
        '.png': 'image/png',
        '.jpg': 'image/jpg',
        '.svg': 'image/svg+xml',
        '.css': 'text/css',
        '.js': 'application/x-javascript',
        '.wasm': 'application/wasm',
        '.json': 'application/json',
        '.xml': 'application/xml',
        '.gz': 'application/gzip',
        '.Z': 'application/octet-stream',
        '.bz2': 'application/x-bzip2',
        '.xz': 'application/x-xz',
    }

    # ToDo: Добавить чтоб реагировал только на files.
    # ToDo: Сделать красивую страницу
    # ToDo: Сделать футер с донатом
    # ToDo: Сделать main page
    # ToDo: асинхронная работа с БД

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            try:
                self.copyfile(f, self.wfile)
            finally:
                f.close()

    def send_head(self):
        original_filename = self.translate_path(self.path)

        if os.path.isdir(original_filename):
            return self.list_directory(original_filename)
        path = self.path.split("/")
        if len(path) > 3:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        if len(path) == 2:
            base, ext = posixpath.splitext(path[1])
            if ext != "":
                path[1] = base
                path.append(base + ext)
        if __db__.is_exist(path[1]):
            stored_file = __db__.find_file(path[1])
            if stored_file.is_short_link:
                stored_file.downloads_number += 1
                stored_file.last_access = time_ns()
                if len(path) == 3:
                    stored_file.add_name(path[2])
                __db__.replace_file(path[1], stored_file)
                stored_file = __db__.find_file(stored_file.original_hash)
            if len(path) == 3:
                stored_file.add_name(path[2])
            stored_file.downloads_number += 1
            stored_file.last_access = time_ns()
            __db__.replace_file(path[1], stored_file)
            path = self.translate_path("/"+stored_file.hash)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        f = None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if "If-Modified-Since" in self.headers and "If-None-Match" not in self.headers:
                # compare If-Modified-Since and time of last file modification
                try:
                    ims = email.utils.parsedate_to_datetime(
                        self.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None
            ctype = self.guess_type(original_filename)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()

            return f
        except:
            f.close()
            raise

    def do_POST(self):

        """Serve a POST request."""
        # upload file
        result, message = self.handle_upload()

        r = []
        enc = sys.getfilesystemencoding()

        # html code of upload result page
        r.append('<!DOCTYPE HTML>')
        r.append('<html>\n<title>Upload result</title>')
        r.append('<body>\n<h1>Upload result</h1>')
        if result:
            r.append('<b><font color="green">File(s) successfully uploaded</font></b>: ')
            for key, value in message.items():
                r.append(f'<a href="https://localhost:8000/{value}/{key}">{key}</a><br />')
        else:
            r.append('<b><font color="red">Failed to upload file(s)</font></b>: ')
            r.append(message)
        r.append(f'<br /><br />\n<a href=\"{self.headers["referer"]}\">Go back</a>')
        r.append('</body>\n</html>')

        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()

        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def handle_upload(self):
        """Handle the file upload."""

        # extract boundary from headers
        boundary = re.search(f'boundary=([^;]+)', self.headers['content-type']).group(1)

        if int(self.headers['content-length']) > 1000000000:
            return False, 'file(s) are too big'

        # read all bytes (headers included)
        # 'readlines()' hangs the script because it needs the EOF character to stop,
        # even if you specify how many bytes to read
        # 'file.read(nbytes).splitlines(True)' does the trick because 'read()' reads 'nbytes' bytes
        # and 'splitlines(True)' splits the file into lines and retains the newline character
        data = self.rfile.read(int(self.headers['content-length'])).splitlines(True)

        # find all filenames
        filenames = re.findall(f'{boundary}.+?filename="(.+?)"', str(data))

        if not filenames:
            return False, 'couldn\'t find file name(s).'

        # find all boundary occurrences in data
        boundary_indices = list((i for i, line in enumerate(data) if re.search(boundary, str(line))))

        result = {}

        # save file(s)
        for i in range(len(filenames)):
            # remove file headers
            file_data = data[(boundary_indices[i] + 4):boundary_indices[i + 1]]

            # join list of bytes into bytestring
            file_data = b''.join(file_data)

            hash_id = urlsafe_b64encode(sha3_384(file_data).digest()).decode()

            if __db__.is_exist(hash_id):
                stored_file = __db__.find_file(hash_id)
                stored_file.add_name(filenames[i])
                stored_file.uploads_number += 1
                __db__.replace_file(hash_id, stored_file)
            else:
                stored_file = storedFile.StoredFile(hash_id,
                                                    size=len(file_data),
                                                    uploads_number=1,
                                                    name=[storedFile.Name(filenames[i],
                                                                          uploads_number=1)])
                __db__.insert_file(stored_file)

            # write to file
            try:
                with open(f'{args.directory}/{hash_id}', 'wb') as file:
                    file.write(file_data)
            except IOError:
                return False, f'couldn\'t save {sanitize_filename(filenames[i])}.'

            result[sanitize_filename(filenames[i])] = hash_id

        return True, result

    def list_directory(self, path):
        r = []
        enc = sys.getfilesystemencoding()
        r.append('<h1>File upload</h1>\n<hr>')
        r.append('<form id="upload" enctype="multipart/form-data" method="post" action="#">')
        r.append('<input id="fileupload" name="file" type="file" multiple />')
        r.append('<input type="submit" value="Submit" id="submit" />')
        r.append('</form>')
        r.append('<hr>\n</body>\n</html>')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'text/html; charset=%s' % enc)
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        return f


def test(HandlerClass=http.server.BaseHTTPRequestHandler,
         ServerClass=http.server.ThreadingHTTPServer,
         protocol='HTTP/1.0', port=8000, bind=None):
    """Test the HTTP request handler class.
    This runs an HTTP server on port 8000 (or the port argument).
    """
    ServerClass.address_family, addr = http.server._get_best_family(bind, port)

    HandlerClass.protocol_version = protocol
    with ServerClass(addr, HandlerClass) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        url_host = f'[{host}]' if ':' in host else host
        print(
            'Serving HTTP' + ('S' if args.certificate else '') + f' on {host} port {port} '
                                                                 '(http' + (
                's' if args.certificate else '') + f'://{url_host}:{port}/) ...'
        )
        # add ssl to http connection if certificate was specified
        if args.certificate:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=args.certificate, server_side=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nKeyboard interrupt received, exiting.')
            sys.exit(0)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', '-b', metavar='ADDRESS',
                        help='Specify alternate bind address '
                             '[default: all interfaces]')
    parser.add_argument('--directory', '-d', default=os.getcwd(),
                        help='Specify alternative directory '
                             '[default: current directory]')
    parser.add_argument('--certificate', '-c', metavar='PATH_TO_CERTIFICATE',
                        help='Your SSL certificate in the .pem file format '
                             '[default: none]')
    parser.add_argument('port', action='store',
                        default=8000, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8000]')
    args = parser.parse_args()
    handler_class = partial(SimpleHTTPRequestHandlerWithUpload,
                            directory=args.directory)


    # ensure dual-stack is not disabled; ref #38907
    class DualStackServer(http.server.ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            return super().server_bind()


    test(
        HandlerClass=handler_class,
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind
    )
