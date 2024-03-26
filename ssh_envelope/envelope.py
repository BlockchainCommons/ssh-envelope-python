class Envelope:
    def __init__(self, value: str):
        self._value = value

    def __repr__(self):
        return self._value

    def __eq__(self, other):
        if isinstance(other, Envelope):
            return self._value == other._value
        return False

    def __hash__(self):
        return hash(self._value)

    @property
    def value(self):
        return self._value
