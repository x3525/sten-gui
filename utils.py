"""General utilities."""

import os
from typing import Tuple


def splitext(path: str) -> Tuple[str, str]:
    """Split the pathname `path` into a pair."""
    _, tail = os.path.split(path)

    _, sep, after = tail.rpartition('.')

    extension = f'.{after}' if sep else ''

    filename = path.removesuffix(extension)

    return filename, extension
