"""Database module."""

import sqlite3


class Db:
    """Database management class."""

    def __init__(self, name: str, table: str, *defaults: tuple[str, str]):
        self.name = name
        self.table = table
        self.defaults = defaults

    def fetch(self) -> list[tuple[str, str]]:
        """Fetch data from the database."""
        con = sqlite3.connect(self.name)
        cur = con.cursor()
        try:
            cur.execute(f'CREATE TABLE {self.table}(k,v)')
        except sqlite3.Error:
            pass
        else:
            params = self.defaults
            cur.executemany(f'INSERT INTO {self.table} VALUES(?,?)', params)
            con.commit()
        finally:
            result = cur.execute(f'SELECT * FROM {self.table}')
            data = result.fetchall()
            con.close()
        return data

    def update(self, *params: tuple[str, str]):
        """Update the database."""
        con = sqlite3.connect(self.name)
        cur = con.cursor()
        try:
            cur.executemany(f'UPDATE {self.table} SET v=? WHERE k=?', params)
            con.commit()
        except sqlite3.Error:
            pass
        finally:
            con.close()
