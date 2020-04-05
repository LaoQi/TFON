"""
protocol
{
    big endian
    header {
        4 byte magic number 0x5f3759df
        2 byte version
        2 byte header length
        4 byte data length
        8 byte timestamp
        32 byte sha-256 hash
        ...
    }
    data
}
"""
import hashlib
import struct
import io

MAGIC_NUMBER = 0x5f3759df


class BlockParseError(Exception):
    pass


class Block:
    def __init__(self):
        self.timestamp = 0
        self.data = None
        self.hash = None

    @staticmethod
    def get_version():
        return 1

    @staticmethod
    def get_header_length():
        # always 52
        return 52

    def length(self):
        return self.get_header_length() + self.get_data_length()

    def get_data_length(self):
        if self.data:
            return len(self.data)
        else:
            return 0

    def data_hash(self) -> bytes:
        sha = hashlib.sha256()
        sha.update(self.data)
        return sha.digest()

    def get_data_hash(self) -> bytes:
        if self.hash:
            return self.hash
        return self.data_hash()

    def get_data(self) -> bytes:
        if not self.data:
            return b''
        return self.data

    def load(self, raw_data: bytes) -> int:
        # return offset
        if raw_data[:4] != MAGIC_NUMBER:
            raise BlockParseError("not start with magic number!")
        self.timestamp = int(struct.unpack(">Q", raw_data[12:20])[0])
        self.hash = raw_data[20:52]
        data_length = int(struct.unpack(">L", raw_data[8:12])[0])
        self.data = raw_data[52:data_length]
        return 52 + data_length

    def dump(self) -> bytes:
        header = struct.pack(">LHHLQs",
                             MAGIC_NUMBER, self.get_version(), self.get_header_length(),
                             self.get_data_length(), self.timestamp, self.get_data_hash())
        return header + self.get_data()


class Frank:
    def __init__(self):
        self._phrase = None
        self._blocks = []
        self.raw_data = None

    def password(self, value):
        self._phrase = value

    def encrypt(self):
        if not self._phrase or not self.raw_data:
            return

    def load(self, raw_data: bytes):
        self.raw_data = raw_data
        self.decrypt()
        offset = 0
        while True:
            block = Block()
            try:
                offset = block.load(raw_data[offset:])
                self._blocks.append(block)
            except BlockParseError:
                break

    def dumps(self):
        buffer = io.BufferedIOBase()
        for i in self._blocks:
            buffer.write(i.dump())
        return buffer.read()

    def decrypt(self):
        if not self._phrase or not self._blocks:
            pass


if __name__ == "__main__":
    frank = Frank()

