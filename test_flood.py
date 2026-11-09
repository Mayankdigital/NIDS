import urllib.request, socket, http.client
def fetch(src):
    try:
        class BoundHTTPHandler(urllib.request.HTTPHandler):
            def http_open(self, req):
                return self.do_open(lambda *a, **k: http.client.HTTPConnection(*a, source_address=(src, 0), **k), req)
        opener = urllib.request.build_opener(BoundHTTPHandler)
        with opener.open('http://127.0.0.1:8080/', timeout=2) as r: print(src, r.getcode())
    except Exception as e: print(src, type(e))
fetch('127.0.0.2')
fetch('127.0.0.3')
