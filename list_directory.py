 def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).
        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().
        """
        try:
            list_dir = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list_dir.sort(key=lambda a: a.lower())
        f = BytesIO()
        display_path = escape(unquote(self.path))
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<html>\n<title>Directory listing for %s</title>\n" % display_path.encode('utf-8'))
        f.write(b"<body>\n<h2>Directory listing for %s</h2>\n" % display_path.encode('utf-8'))
        f.write(b"<hr>\n")
        f.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
        f.write(b"<input name=\"file\" type=\"file\"/>")
        f.write(b"<input type=\"submit\" value=\"upload\"/></form>\n")
        f.write(b"<hr>\n<ul>\n")
        for name in list_dir:
            fullname = os.path.join(path, name)
            display_name = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                display_name = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                display_name = name + "@"
                # Note: a link to a directory displays with @ and links with /
            f.write(b'<li><a href="%s">%s</a>\n' % (quote(linkname).encode('utf-8'), escape(display_name).encode('utf-8')))
        f.write(b"</ul>\n<hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f


import os
from io import BytesIO

def unquote(string, encoding='utf-8', errors='replace'):
    if isinstance(string, bytes):
        return unquote_to_bytes(string).decode(encoding, errors)
    if '%' not in string:
        string.split
        return string
    if encoding is None:
        encoding = 'utf-8'
    if errors is None:
        errors = 'replace'
    bits = _asciire.split(string)
    res = [bits[0]]
    append = res.append
    for i in range(1, len(bits), 2):
        append(unquote_to_bytes(bits[i]).decode(encoding, errors))
        append(bits[i + 1])
    return ''.join(res)

def quote(string, safe='/', encoding=None, errors=None):
    if isinstance(string, str):
        if not string:
            return string
        if encoding is None:
            encoding = 'utf-8'
        if errors is None:
            errors = 'strict'
        string = string.encode(encoding, errors)
    else:
        if encoding is not None:
            raise TypeError("quote() doesn't support 'encoding' for bytes")
        if errors is not None:
            raise TypeError("quote() doesn't support 'errors' for bytes")
    return quote_from_bytes(string, safe)

def list_directory(self, directory_path):
    """Generate a directory listing (excluding index.html).
    Returns a file object or None in case of an error. Headers are sent, aligning with send_head() interface.
    """
    try:
        directory_contents = os.listdir(directory_path)
    except os.error:
        self.send_error(404, "No permission to list directory")
        return None

    # Sort directory contents alphabetically
    directory_contents.sort(key=lambda item: item.lower())

    html_content_buffer = BytesIO()
    display_path = escape(unquote(self.path)).encode('utf-8')

    # HTML header
    html_content_buffer.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
    html_content_buffer.write(b"<html>\n<title>Directory listing for %s</title>\n" % display_path)
    html_content_buffer.write(b"<body>\n<h2>Directory listing for %s</h2>\n" % display_path)
    html_content_buffer.write(b"<hr>\n")

    # File upload form
    html_content_buffer.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
    html_content_buffer.write(b"<input name=\"file\" type=\"file\"/>")
    html_content_buffer.write(b"<input type=\"submit\" value=\"upload\"/></form>\n")
    html_content_buffer.write(b"<hr>\n<ul>\n")

    # List directory content
    for entry_name in directory_contents:
        entry_full_path = os.path.join(directory_path, entry_name)
        display_name, link_name = self.get_display_and_link_names(entry_full_path, entry_name)

        html_content_buffer.write(b'<li><a href="%s">%s</a>\n' % (quote(link_name).encode('utf-8'), escape(display_name).encode('utf-8')))

    # HTML footer
    html_content_buffer.write(b"</ul>\n<hr>\n</body>\n</html>\n")

    html_length = html_content_buffer.tell()
    html_content_buffer.seek(0)

    # Send response headers
    self.send_response(200)
    self.send_header("Content-type", "text/html;charset=utf-8")
    self.send_header("Content-Length", str(html_length))
    self.end_headers()

    # Return the HTML content as a file object
    return html_content_buffer
