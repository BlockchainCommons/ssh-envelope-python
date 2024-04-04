import base64

class PEM:
    def __init__(self, header: str, data: bytes):
        self._header = header
        self._data = data
        self._pem_string = ""
        self._encode_pem()

    @classmethod
    def from_pem_string(cls, pem_string: str):
        header, decoded_data = cls._parse_pem(pem_string)
        return cls(header, decoded_data)

    @classmethod
    def from_header_and_data(cls, header: str, data: bytes):
        return cls(header, data)

    @staticmethod
    def _parse_pem(pem_string: str):
        lines = pem_string.strip().split("\n")

        if not lines:
            raise ValueError("Empty PEM data")

        header = lines[0].strip()
        footer = lines[-1].strip()

        if not header.startswith("-----BEGIN"):
            raise ValueError("Invalid PEM header")

        if not footer.startswith("-----END"):
            raise ValueError("Invalid PEM footer")

        header_type = header[11:-5]
        footer_type = footer[9:-5]

        if header_type != footer_type:
            raise ValueError("PEM header and footer do not match")

        base64_data = "".join(lines[1:-1]).replace(" ", "").replace("\t", "")
        decoded_data = base64.b64decode(base64_data)

        return header_type, decoded_data

    def _encode_pem(self):
        base64_data = base64.b64encode(self._data).decode("utf-8")
        pem_lines = [f"-----BEGIN {self._header}-----"]
        pem_lines.extend(base64_data[i:i+64] for i in range(0, len(base64_data), 64))
        pem_lines.append(f"-----END {self._header}-----")
        self._pem_string = "\n".join(pem_lines) + "\n"

    def __eq__(self, other):
        if isinstance(other, PEM):
            return self._header == other._header and self._data == other._data
        return False

    @property
    def header(self):
        return self._header

    @property
    def data(self):
        return self._data

    @property
    def pem_string(self):
        return self._pem_string
