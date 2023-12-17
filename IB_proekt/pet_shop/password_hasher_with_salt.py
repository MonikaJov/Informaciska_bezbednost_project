import bcrypt


class PasswordHasher:
    def hash_password(self, password):
        password = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password_bytes = bcrypt.hashpw(password, salt)
        hashed_password_str = hashed_password_bytes.decode('utf-8')
        return hashed_password_str

    def check_password(self, input_password, stored_password):
        input_password = input_password.encode('utf-8')
        stored_password_bytes = stored_password.encode('utf-8')
        return bcrypt.checkpw(input_password, stored_password_bytes)

