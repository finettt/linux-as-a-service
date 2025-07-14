from typing import Dict
from src.laas.exceptions.AnotherKeyError import AnotherKeyError
from src.laas.history import History
from src.laas.utils.execute_command import execute_command


import jwt
import rsa


import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
load_dotenv()

class Session():
    session_ttl = os.getenv("SESSION_TTL")
    def __init__(self,id: int):
        if type(id) is not int:
            raise TypeError("Type of id might be int!")
        self.__rsa_private = ""
        self.id = id
        self.__token = ""
        self.__secret_key = None
        self.history = History([])
        self.__pwd = "/"
    def generate_token(self, username: str):
        if self.__secret_key is None:
            raise ValueError("Set secret key before generating token!")
        payload = {
            "user_id": self.id,
            "username": username,
            "exp": datetime.now(timezone.utc) + timedelta(hours=Session.session_ttl)
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

    def decrypt_password(self, hex_cipher: str):
        cipherpassword = bytes.fromhex(hex_cipher)
        dec_password = ""
        try:
            dec_password = rsa.decrypt(cipherpassword, self.__rsa_private).decode('utf8')
        except rsa.pkcs1.DecryptionError:
            raise AnotherKeyError("It looks like your password is encrypted with a different RSA key.")
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
        
    def __repr__(self):
        return self.history.get_history()
    
    def to_dict(self):
        return {
            "id": self.id,
            "token":self.__token,
            "secret_key":self.__secret_key,
            "history":self.history.get_history(),
            "pwd":self.__pwd
        }
    
    def get_rsa_private(self):
        return {
                'e': self.__rsa_private.e,
                'd': self.__rsa_private.d,
                'p': self.__rsa_private.p,
                'q': self.__rsa_private.q,
                'n': self.__rsa_private.n,
                },

    @classmethod
    def from_dict(self, session_dict: Dict, rsa_private):
        self.id: int = session_dict.get("id")
        self.__token = session_dict.get("token")
        self.set_secret_key(
            session_dict.get("secret")
        )
        self.set_rsa_private(rsa_private=rsa_private)
        self.history = History(session_dict.get("history"))
        self.__pwd = session_dict.get("pwd")