"""Ciphers."""

import itertools
import math
import operator
import re
import string
from abc import ABC, abstractmethod
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from error import (
    MatrixNotInvertibleException,
    NotCoPrimeException,
    ZeroShiftException,
)

_ALPHABET = string.printable
_ALPHABET_LEN = len(_ALPHABET)

# = Custom Type Hints =
_TIntArray = NDArray[np.int32]

_TJob = Literal['+', '-']

_TOrd = Literal['ij', 'ji']

# https://www.tcl.tk/man/tcl/TkCmd/entry.html#M16
_TVCMDCode = Literal['%d', '%i', '%P', '%s', '%S', '%v', '%V', '%W']

# = Validate Actions =
_DELETE = '0'
_INSERT = '1'


class _Cipher(ABC):
    """Abstract base class for cipher classes."""

    name: str
    code: tuple[_TVCMDCode, _TVCMDCode]

    def __init__(self, text: str):
        self._text = text

    @property
    def text(self) -> str:
        """Plain/cipher text."""
        return self._text

    @text.setter
    def text(self, value: str):
        self._text = value

    @staticmethod
    @abstractmethod
    def validate(action: _TVCMDCode, data: _TVCMDCode) -> bool:
        """Validate command."""

    @abstractmethod
    def encrypt(self) -> str:
        """Encrypt."""

    @abstractmethod
    def decrypt(self) -> str:
        """Decrypt."""


class _NotACipher(_Cipher):
    """Not a cipher."""

    name = ''
    code = ('%d', '%S')

    def __init__(self, key: str, text: str = ''):
        super().__init__(text)

        self._key = key

    @staticmethod
    def validate(action: _TVCMDCode, data: _TVCMDCode) -> bool:
        """Validate command."""
        return False

    def encrypt(self) -> str:
        """Encrypt."""
        return self.text

    def decrypt(self) -> str:
        """Decrypt."""
        return self.text


class _Caesar(_Cipher):
    """Caesar cipher."""

    name = 'Caesar'
    code = ('%d', '%S')

    def __init__(self, key: str, text: str = ''):
        super().__init__(text)

        self._key = int(key)

        if (self._key % _ALPHABET_LEN) == 0:
            raise ZeroShiftException('Key error. Shift value is equal to 0.')

    @staticmethod
    def validate(action: _TVCMDCode, data: _TVCMDCode) -> bool:
        """Validate command."""
        return (action == _DELETE) or data.isdigit()

    def encrypt(self) -> str:
        """Encrypt."""
        return self._do_it('+')

    def decrypt(self) -> str:
        """Decrypt."""
        return self._do_it('-')

    def _do_it(self, job: _TJob) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        text = ''
        for char in self.text:
            c_idx_text = _ALPHABET.index(char)
            c_idx_key = self._key

            text += _ALPHABET[jobs[job](c_idx_text, c_idx_key) % _ALPHABET_LEN]

        return text


class _Hill(_Cipher):
    """Hill cipher."""

    name = 'Hill'
    code = ('%d', '%S')

    def __init__(self, key: str, text: str = ''):
        super().__init__(text)

        self._row = math.ceil(math.sqrt(len(key)))

        self._key = self._m_fill(key, shape=(self._row, self._row), order='ij')

        determinant = round(np.linalg.det(self._key))

        if determinant == 0:
            raise MatrixNotInvertibleException('Key matrix is not invertible.')
        if math.gcd(determinant, _ALPHABET_LEN) != 1:
            raise NotCoPrimeException(
                'Key determinant and alphabet length are not co-prime.'
            )

        self._m_adj = np.linalg.inv(self._key) * determinant

        self._det_inv = pow(determinant, -1, _ALPHABET_LEN)

    @staticmethod
    def validate(action: _TVCMDCode, data: _TVCMDCode) -> bool:
        """Validate command."""
        return (action == _DELETE) or (data in _ALPHABET)

    @staticmethod
    def _m_fill(vals: str, shape: tuple[int, int], order: _TOrd) -> _TIntArray:
        """Create a new matrix and fill it."""
        orders = {
            'ij': lambda *given: given,
            'ji': lambda *given: given[::-1],
        }

        matrix = np.zeros(shape=shape, dtype=int)

        row, col = orders[order](*shape)

        fill = 0
        idx = 0
        for i, j in itertools.product(range(row), range(col)):
            if idx == len(vals):
                matrix[orders[order](i, j)] = fill
                fill += 1
                continue

            matrix[orders[order](i, j)] = _ALPHABET.index(vals[idx])
            idx += 1

        return matrix

    def _m_multiply(self, matrix: NDArray) -> _TIntArray:
        """Multiply the given matrix by the column vectors."""
        col = math.ceil(len(self.text) / self._row)

        vectors = self._m_fill(self.text, shape=(self._row, col), order='ji')

        m_multiplied = np.matmul(matrix.astype(int), vectors)
        m_transposed = np.transpose(m_multiplied)

        return np.concatenate(m_transposed) % _ALPHABET_LEN

    def encrypt(self) -> str:
        """Encrypt."""
        return ''.join(_ALPHABET[_] for _ in self._m_multiply(self._key))

    def decrypt(self) -> str:
        """Decrypt."""
        m_inv = np.array(np.around(self._m_adj * self._det_inv))

        return ''.join(_ALPHABET[_] for _ in self._m_multiply(m_inv))


class _Scytale(_Cipher):
    """Scytale cipher."""

    name = 'Scytale'
    code = ('%d', '%P')

    def __init__(self, key: str, text: str = ''):
        super().__init__(text)

        self._key = int(key)

    @staticmethod
    def validate(action: _TVCMDCode, data: _TVCMDCode) -> bool:
        """Validate command."""
        return (action == _DELETE) or bool(re.match(r'[1-9]\d*$', data))

    def encrypt(self) -> str:
        """Encrypt."""
        return ''.join(self.text[_::self._key] for _ in range(self._key))

    def decrypt(self) -> str:
        """Decrypt."""
        rows_, mod = divmod(len(self.text), self._key)

        rows = rows_ + (mod > 0)

        middle = rows * mod

        text = []
        for row in range(rows_):
            text.append(self.text[row:middle:rows])
            text.append(self.text[(middle + row)::rows_])
        text.append(self.text[rows_:middle:rows])

        return ''.join(text)


class _Vigenere(_Cipher):
    """Vigenère cipher."""

    name = 'Vigenère'
    code = ('%d', '%S')

    def __init__(self, key: str, text: str = ''):
        super().__init__(text)

        self._key = key

    @staticmethod
    def validate(action: _TVCMDCode, data: _TVCMDCode) -> bool:
        """Validate command."""
        return (action == _DELETE) or (data in _ALPHABET)

    def encrypt(self) -> str:
        """Encrypt."""
        return self._do_it('+')

    def decrypt(self) -> str:
        """Decrypt."""
        return self._do_it('-')

    def _do_it(self, job: _TJob) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        key = iter((self._key * len(self.text))[:len(self.text)])

        text = ''
        for char in self.text:
            c_idx_text = _ALPHABET.index(char)
            c_idx_key = _ALPHABET.index(next(key))

            text += _ALPHABET[jobs[job](c_idx_text, c_idx_key) % _ALPHABET_LEN]

        return text


ciphers: dict[str, type[_Cipher]] = {
    (NAC := _NotACipher.name): _NotACipher,
    (CAESAR := _Caesar.name): _Caesar,
    (HILL := _Hill.name): _Hill,
    (SCYTALE := _Scytale.name): _Scytale,
    (VIGENERE := _Vigenere.name): _Vigenere,
}
