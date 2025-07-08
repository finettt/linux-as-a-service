from typing import List, Optional
from src.laas.session import Session


import rsa


class SessionManager():
    def __init__(self):
        self.__sessions: List[Session] = []

    def get_free_id(self) -> int:
        existing_ids = sorted([obj.id for obj in self.__sessions])
        if not existing_ids:
            return 0
        if existing_ids[0] != 0:
            return 0
        for i in range(len(existing_ids) - 1):
            if existing_ids[i+1] > existing_ids[i] + 1:
                return existing_ids[i] + 1
        return existing_ids[-1] + 1

    def request_session(self):
        free_id = self.get_free_id()
        new_session = Session(id=free_id)
        (publicKey, privateKey) = rsa.newkeys(2048)
        new_session.set_rsa_private(privateKey)
        self.__append_session(new_session)
        publicKey_json = {
            'n': publicKey.n,
            'e': publicKey.e
        }
        return {"id":free_id,"pubKey": publicKey_json}

    def register_session(self, session_id: int, username: str, hex_cipher: str):
        session: Session = self.find_session_by_id(session_id)
        if session!=None:
            try:
                secret_key = session.decrypt_password(hex_cipher=hex_cipher)
            except ValueError as e:
                return {"error":f"Invalid cipher: {str(e)}"}
            
            session.set_secret_key(secret_key=secret_key)
            return {"id":session_id, "token":session.generate_token(username=username)}
        else:
            return {"error":f"Session {session_id} does not exists!"}
        
    def auth_session(self, session_id: int, encoded_jwt: str):
        session: Session = self.find_session_by_id(session_id)
        if session!=None:
            val_result = session.validate(encoded_jwt)
            if val_result.get("val") != "Session validation success!":
                return val_result
            else:
                return {"auth": "Session auth success!"}
        else:
            return {"error":f"Session {session_id} does not exists!"}
    def find_session_by_id(self,id: int) -> Optional[Session]:
        session: Session = next((tmp_session for tmp_session in self.__sessions if tmp_session.id == id), None)
        return session

    def find_session_by_token(self,token: str) -> Optional[Session]:
        session: Session = next((tmp_session for tmp_session in self.__sessions if tmp_session.get_token() == token), None)
        return session
    
    def get_session_c(self):
        return len(self.__sessions)
    
    def get_sessions(self):
        return [{"id":obj.id,"token":obj.get_token()} for obj in self.__sessions]
    
    def __append_session(self, session: Session):
        self.__sessions.append(session)