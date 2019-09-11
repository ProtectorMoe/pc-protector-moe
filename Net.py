import requests
import requests.exceptions

HEADER = {'Accept-Encoding': 'identity',
          'Connection': 'Keep-Alive',
          'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 5.1.1; mi max Build/LMY48Z)'}


class Session:
    def __init__(self):
        self.session = requests.session()

    def new_session(self):
        self.session = requests.session()
        self.session.keep_alive = False

    def get(self, url, **kwargs):
        for i in range(5):
            try:
                r = self.session.get(url=url, **kwargs)
                r.close()
                return r
            except requests.exceptions.ConnectTimeout:
                if i == 4:
                    raise

    def post(self, url, data=None, json=None, **kwargs):
        for i in range(5):
            try:
                r = self.session.post(url=url, data=data, json=json, **kwargs)
                r.close()
                return r
            except requests.exceptions.ConnectTimeout:
                if i == 4:
                    raise

session = Session()
