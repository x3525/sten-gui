"""Custom exceptions."""


class StenError(Exception):
    """Base class for all other Sten exceptions."""


class CryptoErrorGroup(StenError):
    """A combination of multiple crypto exceptions."""
