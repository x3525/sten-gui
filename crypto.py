"""Ciphers."""

import math
import operator
import re
import string
from abc import ABC, abstractmethod
from itertools import product
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from error import MatrixNotInvertibleError, NotCoPrimeError, ZeroShiftError

ALPHABET_LEN = len(ALPHABET := string.printable)

# = Custom Type Hints =
TJob = Literal['+', '-']
TOrder = Literal['ij', 'ji']
TIntArr = NDArray[np.int32]
# https://www.tcl.tk/man/tcl/TkCmd/entry.html#M16
TVCMDCode = Literal['%d', '%i', '%P', '%s', '%S', '%v', '%V', '%W']

# = Validate Actions =
DELETE = '0'
INSERT = '1'


class Cipher(ABC):
    """Abstract base class for cipher classes."""

    name: str
    code: tuple[TVCMDCode, TVCMDCode]

    def __init__(self, text: str):
        self._text = text

    @property
    def text(self) -> str:
        """Plain/cipher text."""
        return self._text

    @text.setter
    def text(self, text: str):
        self._text = text

    @staticmethod
    @abstractmethod
    def validate(action: TVCMDCode, data: TVCMDCode) -> bool:
        """Validate command."""

    @abstractmethod
    def encrypt(self) -> str:
        """Encrypt."""

    @abstractmethod
    def decrypt(self) -> str:
        """Decrypt."""


class NotACipher(Cipher):
    """Not a cipher."""

    name = ''
    code = ('%d', '%S')

    def __init__(self, key: str, text=''):
        super().__init__(text)

        self._key = key

    @staticmethod
    def validate(action, data):
        """Validate command."""
        return False

    def encrypt(self):
        """Encrypt."""
        return self.text

    def decrypt(self):
        """Decrypt."""
        return self.text


class Caesar(Cipher):
    """Caesar cipher."""

    name = 'Caesar'
    code = ('%d', '%S')

    def __init__(self, key: str, text=''):
        super().__init__(text)

        self._key = int(key)

        if (self._key % ALPHABET_LEN) == 0:
            raise ZeroShiftError('Key error. Shift value is equal to 0.')

    @staticmethod
    def validate(action, data):
        """Validate command."""
        return (action == DELETE) or data.isdigit()

    def encrypt(self):
        """Encrypt."""
        return self._do('+')

    def decrypt(self):
        """Decrypt."""
        return self._do('-')

    def _do(self, job: TJob) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        text = ''

        for char in self.text:
            ch_idx_text = ALPHABET.index(char)
            ch_idx_key = self._key

            text += ALPHABET[jobs[job](ch_idx_text, ch_idx_key) % ALPHABET_LEN]

        return text


class Hill(Cipher):
    """Hill cipher."""

    name = 'Hill'
    code = ('%d', '%S')

    def __init__(self, key: str, text=''):
        super().__init__(text)

        self._row = math.ceil(math.sqrt(len(key)))

        self._key = self._m_fill(key, shape=(self._row, self._row), order='ij')

        determinant = round(np.linalg.det(self._key))

        if determinant == 0:
            raise MatrixNotInvertibleError('Key matrix is not invertible.')
        if math.gcd(determinant, ALPHABET_LEN) != 1:
            raise NotCoPrimeError(
                'Key determinant and alphabet length are not co-prime.'
            )

        self._m_adj = np.linalg.inv(self._key) * determinant

        self._det_inv = pow(determinant, -1, ALPHABET_LEN)

    @staticmethod
    def validate(action, data):
        """Validate command."""
        return (action == DELETE) or (data in ALPHABET)

    @staticmethod
    def _m_fill(values: str, shape: tuple[int, int], order: TOrder) -> TIntArr:
        """Create a new matrix and fill it."""
        orders = {
            'ij': lambda *given: given,
            'ji': lambda *given: given[::-1],
        }

        matrix = np.zeros(shape=shape, dtype=int)

        row, col = orders[order](*shape)

        fill, idx = 0, 0

        for i, j in product(range(row), range(col)):
            if idx == len(values):
                matrix[orders[order](i, j)] = fill
                fill += 1
                continue

            matrix[orders[order](i, j)] = ALPHABET.index(values[idx])
            idx += 1

        return matrix

    def _m_multiply(self, matrix: NDArray) -> TIntArr:
        """Multiply the given matrix by the column vectors."""
        col = math.ceil(len(self.text) / self._row)

        vectors = self._m_fill(self.text, shape=(self._row, col), order='ji')

        m_multiplied = np.matmul(matrix.astype(int), vectors)
        m_transposed = np.transpose(m_multiplied)

        return np.concatenate(m_transposed) % ALPHABET_LEN

    def encrypt(self):
        """Encrypt."""
        return ''.join(ALPHABET[_] for _ in self._m_multiply(self._key))

    def decrypt(self):
        """Decrypt."""
        m_inv = np.array(np.around(self._m_adj * self._det_inv))

        return ''.join(ALPHABET[_] for _ in self._m_multiply(m_inv))


class Scytale(Cipher):
    """Scytale cipher."""

    name = 'Scytale'
    code = ('%d', '%P')

    def __init__(self, key: str, text=''):
        super().__init__(text)

        self._key = int(key)

    @staticmethod
    def validate(action, data):
        """Validate command."""
        return (action == DELETE) or bool(re.match(r'[1-9]\d*$', data))

    def encrypt(self):
        """Encrypt."""
        return ''.join(self.text[_::self._key] for _ in range(self._key))

    def decrypt(self):
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


class Vigenere(Cipher):
    """Vigenère cipher."""

    name = 'Vigenère'
    code = ('%d', '%S')

    def __init__(self, key: str, text=''):
        super().__init__(text)

        self._key = key

    @staticmethod
    def validate(action, data):
        """Validate command."""
        return (action == DELETE) or (data in ALPHABET)

    def encrypt(self):
        """Encrypt."""
        return self._do('+')

    def decrypt(self):
        """Decrypt."""
        return self._do('-')

    def _do(self, job: TJob) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        key = iter((self._key * len(self.text))[:len(self.text)])

        text = ''

        for char in self.text:
            ch_idx_text = ALPHABET.index(char)
            ch_idx_key = ALPHABET.index(next(key))

            text += ALPHABET[jobs[job](ch_idx_text, ch_idx_key) % ALPHABET_LEN]

        return text


ciphers = {
    (NAC := NotACipher.name): NotACipher,
    (CAESAR := Caesar.name): Caesar,
    (HILL := Hill.name): Hill,
    (SCYTALE := Scytale.name): Scytale,
    (VIGENERE := Vigenere.name): Vigenere,
}  # type: dict[str, type[Cipher]]
