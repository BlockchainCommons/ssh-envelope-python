class Envelope:
    def __init__(self, ur: str):
        if not ur.startswith("ur:envelope/"):
            raise ValueError("Not an envelope UR")
        self._ur = ur

    def __repr__(self):
        return self._ur

    def __eq__(self, other):
        if isinstance(other, Envelope):
            return self._ur == other._ur
        return False

    def __hash__(self):
        return hash(self._ur)

    @property
    def ur(self):
        return self._ur
