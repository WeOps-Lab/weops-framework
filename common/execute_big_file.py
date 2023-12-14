import requests
from django.http import StreamingHttpResponse


class BigFile(object):
    def __init__(self, url, filename, headers):
        self.url = url
        self.filename = filename
        self.headers = headers

    def download(self, chunk_size=1024):
        """chunk_size int：每次发给前端的数据流大小"""
        resp = requests.get(self.url, headers=self.headers, verify=False, stream=True)

        def generate():
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk

        response = StreamingHttpResponse(generate(), content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{self.filename}"'
        return response
