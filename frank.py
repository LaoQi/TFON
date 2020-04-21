"""

"""
import io
import time
import hashlib
from diff_match_patch import diff_match_patch
from onekey_pb2 import MD5, SHA1, SHA256, SHA384, OneKey

DEFAULT_HASH_METHOD = MD5


class PhraseNotSet(Exception):
    pass


class DecryptFailed(Exception):
    pass


class Frank:
    def __init__(self):
        self._phrase = None
        self._blocks = []
        self.data = OneKey()
        self.raw_data = None
        self._patch = None
        self._full_content = ""
        self._is_changed = False

    @property
    def full_content(self):
        if self._full_content:
            return self._full_content
        dmp = diff_match_patch()
        content = ""
        for block in self.data.blocks:
            patches = dmp.patch_fromText(block.data)
            content, _ = dmp.patch_apply(patches, content)
        self._full_content = content
        return content

    def set_phrase(self, value: bytes):
        self._phrase = value

    def update_content(self, value: str):
        if self.full_content == value:
            return
        self._is_changed = True
        dmp = diff_match_patch()
        patches = dmp.patch_make(self.full_content, value)
        self._patch = dmp.patch_toText(patches)
        self._full_content = value

    def save(self):
        if not self._is_changed or not self._patch:
            return
        if not self._phrase:
            raise PhraseNotSet("phrase not set!")
        block = self.data.blocks.add()
        block.data = self._patch
        block.timestamp = int(time.time())
        block.method = DEFAULT_HASH_METHOD
        block.hash = self._hash_patch()
        self._patch = None
        self._is_changed = False
        self.encrypt()

    def _hash_patch(self, method=DEFAULT_HASH_METHOD) -> bytes:
        if not self._patch:
            return b''
        hash_methods = {
            MD5: 'md5',
            SHA1: 'sha1',
            SHA256: 'sha256',
            SHA384: 'sha384',
        }
        h = hashlib.new(hash_methods.get(method, 'md5'), self._patch.encode('utf8'))
        return h.digest()

    def load(self, raw_data: bytes):
        self.raw_data = raw_data
        self.decrypt()

    def dumps(self):
        return self.raw_data

    def length(self):
        return len(self.data.blocks)

    @staticmethod
    def padding(data: bytes):
        # like pkcs7
        reader = io.BytesIO()
        reader.write(data)
        p = 64 - len(data) % 64
        reader.write(p.to_bytes(1, 'little') * p)
        return reader.getvalue()

    @staticmethod
    def remove_padding(data: bytes):
        # like pkcs7
        p = data[-1]
        if p == 0 and sum(data[-64:]) == 0:
            return data[:-64]
        elif sum(data[0 - p:]) == p*p:
            return data[: 0 - p]
        return data

    @staticmethod
    def luna(phrase, data: bytes):
        keyring = hashlib.sha512(phrase)
        reader = io.BytesIO()
        reader.write(data)
        writer = io.BytesIO()
        reader.seek(0, 0)
        temp = reader.read(64)
        while temp:
            key = keyring.digest()
            for i in range(64):
                b = temp[i] ^ key[i]
                writer.write(b.to_bytes(1, 'little'))
            keyring.update(key)
            temp = reader.read(64)
        return writer.getvalue()

    def encrypt(self):
        if not self._phrase:
            return
        data = self.data.SerializeToString()
        self.raw_data = self.luna(self._phrase, self.padding(data))

    def decrypt(self):
        if not self._phrase or not self.raw_data:
            return
        try:
            data = self.luna(self._phrase, self.raw_data)
            self.data.ParseFromString(self.remove_padding(data))
        except Exception:
            raise DecryptFailed()


if __name__ == "__main__":
    import os

    frank = Frank()
    frank.set_phrase("phrase".encode())
    # t = frank.padding(b'This is test content!This is test content!This is test content!')
    # print(t)
    # test = frank.luna("phrase1", t)
    # print(len(test), test.hex())
    # back = frank.luna("phrase1", test)
    # print(back)
    # print(frank.remove_padding(back))
    if os.path.exists('tmp/save'):
        with open('tmp/save', 'rb') as f:
            frank.load(f.read())
    frank.update_content("test 5\n this is \r\n unknown ")
    frank.save()
    print(frank.length())
    # with open('tmp/save', 'wb') as f:
    #     f.write(frank.dumps())
    print(frank.full_content)
