from src.laas.session import Session


import rsa


class SessionManager():
    def __init__(self):
        self.__sessions = []

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
        new_session = Session(
            id=free_id
        )
        (publicKey, privateKey) = rsa.newkeys(2048)
        new_session.set_rsa_private(privateKey)
        self.__sessions.append(new_session)
        publicKey_json = {
            'n': publicKey.n,
            'e': publicKey.e
        }
        return {"id":free_id,"pubKey": publicKey_json}

    def register_session(self, session_id: int, username: str, hex_cipher: str):
        session: Session = self.__find_session_by_id(session_id)
        try:
            secret_key = session.__decrypt_password(hex_cipher=hex_cipher)
        except ValueError as e:
            return {"error":f"Invalid cipher: {str(e)}"}
        if session!=None:
            session.set_secret_key(secret_key=secret_key)
            return {"id":session_id, "token":session.generate_token(username=username)}
        else:
            return {"error":f"Session {session_id} does not exists!"}
    def auth_session(self, session_id: int, encoded_jwt: str):
        session: Session = self.__find_session_by_id(session_id)
        if session!=None:
            val_result = session.validate(encoded_jwt)
            if val_result!={"val": "Session validation success!"}:
                return val_result
            else:
                return {"auth": "Session auth success!"}
    def __find_session_by_id(self,id: int) -> Session:
        session: Session = next((tmp_session for tmp_session in self.__sessions if tmp_session.id == id), None)
        return session

    def __find_session_by_token(self,token: str) -> Session:
        session: Session = next((tmp_session for tmp_session in self.__sessions if tmp_session.get_token() == token), None)
        return session