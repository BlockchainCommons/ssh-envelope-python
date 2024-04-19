class SSHReadBuffer:
    def __init__(self, data: bytes):
        self.data = data
        self.index = 0

    def read(self, count: int) -> bytes:
        if self.index + count > len(self.data):
            raise ValueError("Buffer underflow")
        bytes_ = self.data[self.index:self.index + count]
        self.index += count
        return bytes_

    def read_int(self) -> int:
        length_data = self.read(4)
        return int.from_bytes(length_data, byteorder="big")

    def read_chunk(self) -> bytes:
        length = self.read_int()
        return self.read(length)

    def read_chunks(self) -> list[bytes]:
        chunks = []
        while self.index < len(self.data):
            chunks.append(self.read_chunk())
        return chunks

    @staticmethod
    def read_chunks_from(data: bytes) -> list[bytes]:
        buf = SSHReadBuffer(data)
        return buf.read_chunks()

    def read_null_terminated_string(self) -> str:
        bytes_ = b""
        while True:
            byte = self.read(1)
            if byte == b"\x00":
                break
            bytes_ += byte
        return bytes_.decode("utf-8")

    def read_length_prefixed_string(self) -> str:
        length = self.read_int()
        data = self.read(length)
        return data.decode("utf-8")

    def expect_padding(self):
        padding_needed = 8 - (self.index % 8)
        expected_padding = b"\x01\x02\x03\x04\x05\x06\x07"[:padding_needed]
        padding = self.read(padding_needed)
        if padding != expected_padding:
            raise ValueError("Invalid padding")

    @property
    def is_at_end(self) -> bool:
        return self.index == len(self.data)

    @property
    def remaining(self) -> int:
        return len(self.data) - self.index

class SSHWriteBuffer:
    def __init__(self):
        self.data = b""

    def write(self, bytes_: bytes):
        self.data += bytes_

    def write_int(self, n: int):
        self.write(n.to_bytes(4, byteorder="big"))

    def write_chunk(self, chunk: bytes):
        self.write_int(len(chunk))
        self.write(chunk)

    def write_empty_chunk(self):
        self.write_int(0)

    def write_chunks(self, chunks: list[bytes]):
        for chunk in chunks:
            self.write_chunk(chunk)

    @staticmethod
    def chunks_to_data(chunks: list[bytes]) -> bytes:
        buf = SSHWriteBuffer()
        buf.write_chunks(chunks)
        return buf.data

    def write_null_terminated_string(self, string: str):
        self.write(string.encode("utf-8"))
        self.write(b"\x00")

    def write_length_prefixed_string(self, string: str):
        string_data = string.encode("utf-8")
        self.write_int(len(string_data))
        self.write(string_data)

    def write_padding(self):
        padding_needed = 8 - (len(self.data) % 8)
        self.write(b"\x01\x02\x03\x04\x05\x06\x07"[:padding_needed])

    @property
    def length(self) -> int:
        return len(self.data)
