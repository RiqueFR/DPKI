import sqlite3


class DB:
    TABLE_NAME = "user_certificates"

    def __init__(self):
        self.con = sqlite3.connect("data.db")
        self.cur = self.con.cursor()

    def get_certificate_by_user(self, user_id: str):
        try:
            res = self.cur.execute(
                f"SELECT * FROM {self.TABLE_NAME} WHERE user_id = '{user_id}'"
            )
            records = res.fetchone()
            return records
        except Exception:
            return None

    def delete_table(self):
        try:
            self.cur.execute(f"DROP TABLE {self.TABLE_NAME}")
            return True
        except Exception as e:
            return False

    def add_user_certificate(
        self, user_id: str, certificate_hex: str, public_key_hex: str, due_date: str
    ):
        try:
            data = (user_id, certificate_hex, True, public_key_hex, due_date)
            self.cur.execute(
                f"INSERT INTO {self.TABLE_NAME} VALUES(?, ?, ?, ?, ?)", data
            )
            self.con.commit()
            return True
        except Exception as e:
            print(e)
            return False
