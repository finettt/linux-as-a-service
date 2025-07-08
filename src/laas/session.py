from src.laas.history import History
from src.laas.utils.execute_command import execute_command


import jwt
import rsa


import os
from datetime import datetime, timedelta, timezone


class Session():
    def __init__(self,id: int):
        self.__rsa_private = ""
        self.id = id
        self.__token = ""
        self.__secret_key = None
        self.history = History([])
        self.__pwd = "/"
    def generate_token(self, username: str):
        if self.__secret_key==None:
            raise ValueError("Set secret key before generating token!")
        payload = {
            "user_id": self.id,
            "username": username,
            "exp": datetime.now(timezone.utc) + timedelta(hours=0.5)
        }
        self.__token = jwt.encode(payload, self.__secret_key, algorithm="HS256")
        return self.__token

    def get_token(self):
        return self.__token

    def get_pwd(self):
        return self.__pwd

    def set_pwd(self, pwd: str) -> bool:
        if os.path.exists(os.path.join(self.__pwd,pwd)):
            self.__pwd = os.path.join(self.__pwd,pwd)
            return True
        else:
            return False

    def __decrypt_password(self, hex_cipher: str):
        cipherpassword = bytes.fromhex(hex_cipher)
        dec_password = ""
        try:
            dec_password = rsa.decrypt(cipherpassword, self.__rsa_private).decode('utf8')
        except rsa.pkcs1.DecryptionError:
            raise ValueError("It looks like your password is encrypted with a different RSA key.")
        else:
            return dec_password

    def set_rsa_private(self, rsa_private):
        self.__rsa_private = rsa_private

    def set_secret_key(self,secret_key):
        self.__secret_key = secret_key

    def execute_command(self,command):
        result = execute_command(cmdline=command,cwd=self.__pwd)
        self.history.add({
            "command":command,
            "output": result,
        })
        return result

    def validate(self,jwt_token):
        try:
            jwt.decode(jwt_token, self.__secret_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return {"error":"Session has expired!"}
        except jwt.InvalidTokenError:
            return {"error":"Invalid token"}
        else:
            return {"val": "Session validation success!"}