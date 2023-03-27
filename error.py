"""Custom exceptions."""


class StenException(Exception):
    """Base class for all other Sten exceptions."""


class CryptoExceptionGroup(StenException):
    """A combination of multiple crypto exceptions."""


class MatrixNotInvertibleException(CryptoExceptionGroup):
    pass


class NotCoPrimeException(CryptoExceptionGroup):
    pass


class ZeroShiftException(CryptoExceptionGroup):
    pass
