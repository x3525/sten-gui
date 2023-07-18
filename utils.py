"""General utilities."""

import os


def splitext(path: str) -> tuple[str, str]:
    """Split the pathname `path` into a pair."""
    tail = os.path.split(path)[1]

    extension = ''.join(t[1:]) if (t := tail.rpartition('.'))[1] else t[1]

    filename = path.removesuffix(extension)

    return filename, extension
