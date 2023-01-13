"""Custom exceptions."""


class StenException(Exception):
    """Base class for all Sten exceptions."""


class CryptoExceptionGroup(StenException):
    """A combination of multiple crypto exceptions."""


class MatrixNotInvertibleException(CryptoExceptionGroup):
    """Matrix not invertible."""


class NotCoPrimeException(CryptoExceptionGroup):
    """Not co-prime."""


class ZeroShiftException(CryptoExceptionGroup):
    """Zero shift."""
