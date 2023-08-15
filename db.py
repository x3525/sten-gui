"""Database module."""

import sqlite3
from contextlib import contextmanager
from typing import Iterator


class Db:
    """Database management class."""

    def __init__(self, name: str):
        self.name = name

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Cursor]:
        """Open a connection, commit, and then close it automatically."""
        con = sqlite3.connect(self.name)
        cur = con.cursor()
        yield cur
        con.commit()
        con.close()

    def create(self):
        """Create table."""
        with self.connection() as cur:
            cur.execute('CREATE TABLE IF NOT EXISTS _ (_ UNIQUE)')

    def fetchall(self) -> list[tuple[str]]:
        """Fetch all rows."""
        with self.connection() as cur:
            cur.execute('SELECT * FROM _')
            return cur.fetchall()

    def insert(self, rows: list[tuple[str]]):
        """Insert rows."""
        with self.connection() as cur:
            cur.executemany('INSERT OR IGNORE INTO _ VALUES (?)', rows)

    def truncate(self):
        """Truncate table."""
        with self.connection() as cur:
            cur.execute('DELETE FROM _')
