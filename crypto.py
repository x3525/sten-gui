"""Ciphers."""

import math
import operator
import re
import string
from abc import ABC, abstractmethod
from itertools import product
from typing import Any, Literal

import numpy as np
from numpy.typing import NDArray

from error import CryptoExceptionGroup

ALPHABET = string.printable
ALPHABET_LENGTH = len(ALPHABET)

#####################
# Custom Type Hints #
#####################
TArr = NDArray[np.int32]
TJob = Literal['+', '-']
TOrd = Literal['i', 'j']
TVCMDCode = Literal['%d', '%i', '%P', '%s', '%S', '%v', '%V', '%W']

####################
# Validate Actions #
####################
DELETE = '0'
INSERT = '1'


class Cipher(ABC):
    """Abstract base class for cipher classes."""

    name: str
    code: tuple[TVCMDCode, TVCMDCode]

    def __init__(self, key: Any, txt: str = ''):
        self._key = key
        self._txt = txt

    @property
    def key(self) -> Any:
        """Cipher key."""
        return self._key

    @key.setter
    def key(self, key: Any):
        self._key = key

    @property
    def txt(self) -> str:
        """Plain/cipher text."""
        return self._txt

    @txt.setter
    def txt(self, txt: str):
        self._txt = txt

    @staticmethod
    @abstractmethod
    def validate(action: TVCMDCode, data: TVCMDCode) -> bool:
        """Validate command."""
        # https://www.tcl.tk/man/tcl/TkCmd/entry.html#M16

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

    def __init__(self, key: str, txt=''):
        super().__init__(key, txt)

    @staticmethod
    def validate(action, data):
        return False

    def encrypt(self):
        return self.txt

    def decrypt(self):
        return self.txt


class Caesar(Cipher):
    """Caesar cipher."""

    name = 'Caesar'
    code = ('%d', '%S')

    def __init__(self, key: str, txt=''):
        super().__init__(int(key), txt)

        if (self.key % ALPHABET_LENGTH) == 0:
            raise CryptoExceptionGroup('Key error. Shift value is equal to 0.')

    @staticmethod
    def validate(action, data):
        return (action == DELETE) or data.isdigit()

    def encrypt(self):
        return self._do('+')

    def decrypt(self):
        return self._do('-')

    def _do(self, job: TJob) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        txt = ''

        for char in self.txt:
            i_txt = ALPHABET.index(char)
            i_key = self.key

            txt += ALPHABET[jobs[job](i_txt, i_key) % ALPHABET_LENGTH]

        return txt


class Hill(Cipher):
    """Hill cipher."""

    name = 'Hill'
    code = ('%d', '%S')

    def __init__(self, key: str, txt=''):
        super().__init__(key, txt)

        row = math.ceil(math.sqrt(len(key)))

        self.key = self._fill(key, shape=(row, row), order='i')

        determinant = round(np.linalg.det(self.key))

        if determinant == 0:
            raise CryptoExceptionGroup('Key matrix is not invertible.')
        if math.gcd(determinant, ALPHABET_LENGTH) != 1:
            raise CryptoExceptionGroup(
                'Key determinant and alphabet length are not co-prime.'
            )

        self._row = row

        self._adj = np.linalg.inv(self.key) * determinant

        self._inv = pow(determinant, -1, ALPHABET_LENGTH)

    @staticmethod
    def validate(action, data):
        return (action == DELETE) or (data in ALPHABET)

    @staticmethod
    def _fill(values: str, shape: tuple[int, int], order: TOrd) -> TArr:
        """Create a new matrix and fill it."""
        orders = {
            'i': lambda *given: given,
            'j': lambda *given: given[::-1],
        }

        matrix = np.zeros(shape=shape, dtype=int)

        row, col = orders[order](*shape)

        extra, idx = 0, 0

        for i, j in product(range(row), range(col)):
            if idx == len(values):
                matrix[orders[order](i, j)] = extra
                extra += 1
                continue

            matrix[orders[order](i, j)] = ALPHABET.index(values[idx])
            idx += 1

        return matrix

    def _multiply(self, matrix: NDArray) -> TArr:
        """Multiply the given matrix by the column vectors."""
        col = math.ceil(len(self.txt) / self._row)

        vectors = self._fill(self.txt, shape=(self._row, col), order='j')

        multiplied = np.matmul(matrix.astype(int), vectors)
        transposed = np.transpose(multiplied)

        return np.concatenate(transposed) % ALPHABET_LENGTH

    def encrypt(self):
        return ''.join(ALPHABET[i] for i in self._multiply(self.key))

    def decrypt(self):
        inverted = np.array(np.around(self._adj * self._inv))

        return ''.join(ALPHABET[i] for i in self._multiply(inverted))


class Scytale(Cipher):
    """Scytale cipher."""

    name = 'Scytale'
    code = ('%d', '%P')

    def __init__(self, key: str, txt=''):
        super().__init__(int(key), txt)

    @staticmethod
    def validate(action, data):
        return (action == DELETE) or bool(re.match(r'^[1-9]\d*$', data))

    def encrypt(self):
        return ''.join(self.txt[i::self.key] for i in range(self.key))

    def decrypt(self):
        full, mod = divmod(len(self.txt), self.key)

        rows = full + (mod > 0)

        middle = rows * mod

        txt = []

        for row in range(full):
            txt.append(self.txt[row:middle:rows])
            txt.append(self.txt[(middle + row)::full])

        txt.append(self.txt[full:middle:rows])

        return ''.join(txt)


class Vigenere(Cipher):
    """Vigenère cipher."""

    name = 'Vigenère'
    code = ('%d', '%S')

    def __init__(self, key: str, txt=''):
        super().__init__(key, txt)

    @staticmethod
    def validate(action, data):
        return (action == DELETE) or (data in ALPHABET)

    def encrypt(self):
        return self._do('+')

    def decrypt(self):
        return self._do('-')

    def _do(self, job: TJob) -> str:
        """Encrypt/decrypt."""
        jobs = {
            '+': operator.add,
            '-': operator.sub,
        }

        key = iter((self.key * len(self.txt))[:len(self.txt)])

        txt = ''

        for char in self.txt:
            i_txt = ALPHABET.index(char)
            i_key = ALPHABET.index(next(key))

            txt += ALPHABET[jobs[job](i_txt, i_key) % ALPHABET_LENGTH]

        return txt


ciphers = {
    NotACipher.name: NotACipher,
    Caesar.name: Caesar,
    Hill.name: Hill,
    Scytale.name: Scytale,
    Vigenere.name: Vigenere,
}  # type: dict[str, type[Cipher]]
