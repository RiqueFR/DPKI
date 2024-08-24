import sqlite3


class DB:
    TABLE_NAME = "user_certificates"

    def __init__(self):
        """Database inicialization"""
        self.con = sqlite3.connect("data.db")
        self.cur = self.con.cursor()

    def get_certificate_by_user(self, user_id: str):
        """
        Get all atributes of a user

        Args:
            self: database
            user_id (string): user name
        Returns:
            Return tuple with all atributes of a user if user in database, 
            and None if user is not in database.
        """
        try:
            res = self.cur.execute(
                f"SELECT * FROM {self.TABLE_NAME} WHERE user_id = '{user_id}'"
            )
            records = res.fetchone()
            return records
        except Exception:
            return None

    def delete_table(self):
        """Delete database"""
        try:
            self.cur.execute(f"DROP TABLE {self.TABLE_NAME}")
            return True
        except Exception as e:
            return False

    def add_user_certificate(
        self, user_id: str, certificate_hex: str, public_key_hex: str, due_date: str
    ):
        """
        Add new user to database

        Args:
            self: database
            user_id (string): user name
            certificate_hex (string): hexadecimal certificate 
            public_key_hex (string): hexadecimal public key
            due_date( string): certificate expiration date
        Returns:
            Return True if user was correctly added, and False if not.
        """
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

    def update_certificate_status(self, user_id: str, cert_new_status: bool):
        """
        Update the state of a certificate

        Args:
            self: database
            user_id (string): user name
            cert_new_status (bool): new state of certificate
        Returns:
            Return True if user was correctly updated, and False if not.
        """
        try:
            sql = f"UPDATE {self.TABLE_NAME} SET active = ? WHERE user_id = ?"
            self.cur.execute(sql, (cert_new_status, user_id))
            self.con.commit()
            return True
        except Exception as e:
            print(e)
            return False
