import json
from typing import Dict, Optional, Union
from src.laas.exceptions.AnotherKeyError import AnotherKeyError
from src.laas.session import Session
import redis
import rsa

class SessionManager():
    SESSION_COUNTER = 'laas:sessions:counter'
    SESSIONS = 'laas:session:{id}'
    TOKENS = 'laas:token:{token}'
    PRIVATE_KEYS = 'laas:private_key:{id}'
    PRIVATE_KEY_TTL = 300
    RSA_KEY_SIZE = 512 #FIXME: Increase RSA key to 2048


    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    def get_free_id(self) -> int:
        next_id = self.redis.incr(SessionManager.SESSION_COUNTER)
        return next_id

    def request_session(self) -> Dict[str, Union[int, Dict[str, int]]]:
        free_id = self.get_free_id()
        new_session = Session(id=free_id)
        (publicKey, privateKey) = rsa.newkeys(SessionManager.RSA_KEY_SIZE)
        new_session.set_rsa_private(privateKey)
        self.__append_session(new_session)
        publicKey_json = {
            'n': publicKey.n,
            'e': publicKey.e
        }
        return {"id": free_id, "pubKey": publicKey_json}

    def __delete_session(self, session: Session):
        token = session.get_token()
        if token:
            self.redis.delete(SessionManager.TOKENS.format(token=token))
        self.redis.delete(SessionManager.SESSIONS.format(id=session.id))
        return True

    def register_session(self, session_id: int, username: str, hex_cipher: str):
        session_dump = self.find_session_by_id(session_id)
        if session_dump is not None:
            private_key = self.redis.get(SessionManager.PRIVATE_KEYS.format(id=session_dump.get("id")))
            session = Session.from_dict(session_dump, private_key)
            try:
                secret_key = session.decrypt_password(hex_cipher=hex_cipher)
            except AnotherKeyError as e:
                return {"error": f"Invalid cipher: {str(e)}"}
            
            session.set_secret_key(secret_key=secret_key)
            
            data = {"id": session_id, "token": session.generate_token(username=username)}
            pipe = self.redis.pipeline()
            pipe.set(SessionManager.SESSIONS.format(id=session_id),json.dumps(session.to_dict()))
            pipe.set(SessionManager.TOKENS.format(token=session.get_token()),session_id)
            pipe.execute()
            self.redis.delete(SessionManager.PRIVATE_KEYS.format(id=session_dump.get("id")))
            session.set_rsa_private(None)
            return data
        else:
            return {"error": f"Session {session_id} does not exist!"}

    def auth_session(self, session_id: int, encoded_jwt: str):
        session_dump = self.find_session_by_id(session_id)
        if session_dump is not None:
            session: Session = Session.from_dict(session_dump,self.redis.get(SessionManager.PRIVATE_KEYS.format(id=session_dump.get("id"))))
            val_result = session.validate(encoded_jwt)
            if val_result.get("val") == "Session validation success!":
                return {"auth": "Session auth success!"}
            elif val_result.get("error")=="Session has expired!":
                self.__delete_session(session)
            else:
                return val_result
        else:
            return {"error": f"Session {session_id} does not exist!"}

    def find_session_by_id(self, id: int) -> Optional[Dict]:
        session_dump = self.redis.get(SessionManager.SESSIONS.format(id=id))
        if session_dump:
            try:
                session = json.loads(session_dump)
            except json.decoder.JSONDecodeError:
                # FIXME: This may silently fail. Should log invalid session dumps.
                return None
            else:
                return session
        else:
            return None

    def find_session_by_token(self, token: str) -> Optional[Dict]:
        session_id = self.redis.get(SessionManager.TOKENS.format(token=token))
        if session_id:
            return self.find_session_by_id(int(session_id))
        else:
            return None

    def __append_session(self, session: Session):
        with self.redis.pipeline() as pipe:
            pipe.set(
                SessionManager.PRIVATE_KEYS.format(id=session.id),
                json.dumps(session.get_rsa_private()),
                ex=SessionManager.PRIVATE_KEY_TTL
            )
            pipe.set(
                SessionManager.SESSIONS.format(id=session.id),
                json.dumps(session.to_dict())
            )
            pipe.execute()