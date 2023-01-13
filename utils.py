"""General utilities."""

import os
from typing import Tuple


def splitext(path: str) -> Tuple[str, str]:
    """Split the pathname `path` into a pair."""
    _, tail = os.path.split(path)

    extension = f'.{_[-1]}' if (_ := tail.rpartition('.'))[1] else ''

    filename = path.removesuffix(extension)

    return filename, extension
