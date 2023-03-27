"""Custom exceptions."""


class StenError(Exception):
    """Base class for all other Sten exceptions."""


class CryptoErrorGroup(StenError):
    """A combination of multiple crypto exceptions."""


class MatrixNotInvertibleError(CryptoErrorGroup):
    pass


class NotCoPrimeError(CryptoErrorGroup):
    pass


class ZeroShiftError(CryptoErrorGroup):
    pass
