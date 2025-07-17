import json
import logging
from typing import Union, Optional
from uuid import uuid4
from src.laas.exceptions.AnotherKeyError import AnotherKeyError
from src.laas.session import Session
import redis
import rsa

logger = logging.getLogger("my_logger")


class SessionManager:
    SESSION_COUNTER = "laas:sessions:counter"
    SESSIONS = "laas:session:{id}"
    TOKENS = "laas:token:{token}"
    PRIVATE_KEYS = "laas:private_key:{id}"
    PRIVATE_KEY_TTL = 300
    RSA_KEY_SIZE = 512

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def get_free_id(self) -> str:
        return str(uuid4())

    def request_session(self) -> dict[str, Union[str, dict[str, int]]]:
        free_id: str = self.get_free_id()
        new_session = Session(id=free_id)
        (publicKey, privateKey) = rsa.newkeys(SessionManager.RSA_KEY_SIZE)
        new_session.set_rsa_private(privateKey)
        self.__append_session(new_session)
        publicKey_json: dict[str, int] = {"n": publicKey.n, "e": publicKey.e}
        return {"id": free_id, "pubKey": publicKey_json}

    def __delete_session(self, session: Session):
        token = session.get_token()
        if token:
            self.redis.delete(SessionManager.TOKENS.format(token=token))
        self.redis.delete(SessionManager.SESSIONS.format(id=session.id))
        return True

    def register_session(self, session_id: str, username: str, hex_cipher: str):
        session_dump: Session = self.find_session_by_id(str(session_id))
        if session_dump is not None:
            session = session_dump
            try:
                secret_key = session.decrypt_password(hex_cipher=hex_cipher)
            except AnotherKeyError as e:
                return {"error": f"Invalid cipher: {str(e)}"}

            session.set_secret_key(secret_key=secret_key)

            data: dict[str, str] = {
                "id": session_id,
                "token": session.generate_token(username=username),
            }
            with self.redis.pipeline() as pipe:
                pipe.set(
                    SessionManager.SESSIONS.format(id=session_id),
                    json.dumps(session.to_dict()),
                )
                pipe.set(
                    SessionManager.TOKENS.format(token=session.get_token()), session_id
                )
                pipe.delete(SessionManager.PRIVATE_KEYS.format(id=session.id))
                pipe.execute()
            session.set_rsa_private(None)
            return data
        else:
            return {
                "error": f"Session {session_id} does not exist!",
            }

    def auth_session(self, session_id: str, encoded_jwt: str):
        session_dump = self.find_session_by_id(session_id)

        if session_dump is not None:
            session: Session = session_dump
            val_result = session.validate(encoded_jwt)
            if val_result.get("val") == "Session validation success!":
                return {"auth": "Session auth success!"}
            elif val_result.get("error") == "Session has expired!":
                self.__delete_session(session)
            else:
                return val_result
        else:
            return {
                "error": f"Session {session_id} does not exist!",
            }

    def find_session_by_id(self, id: str) -> Optional[Session]:
        session_dump = self.redis.get(SessionManager.SESSIONS.format(id=id))
        if not session_dump:
            return None

        try:
            session_data = json.loads(session_dump)
            rsa_private_dump = self.redis.get(SessionManager.PRIVATE_KEYS.format(id=id))
            if rsa_private_dump:
                rsa_private = json.loads(rsa_private_dump)
                rsa_private = rsa.PrivateKey(
                    rsa_private["n"],
                    rsa_private["e"],
                    rsa_private["d"],
                    rsa_private["p"],
                    rsa_private["q"],
                )
            else:
                rsa_private = None
            session = Session("")
            session.from_dict(session_dict=session_data, rsa_private=rsa_private)
            return session
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            logger.error(f"Failed to deserialize session {id}: {e}")
            return None

    def find_session_by_token(self, token: str) -> Optional[Session]:
        session_id: bytes = self.redis.get(SessionManager.TOKENS.format(token=token))
        if session_id:
            session_id = session_id.decode()
            return self.find_session_by_id(session_id)
        else:
            return None

    def __append_session(self, session: Session):
        with self.redis.pipeline() as pipe:
            pipe.set(
                SessionManager.PRIVATE_KEYS.format(id=session.id),
                json.dumps(session.get_rsa_private()),
                ex=SessionManager.PRIVATE_KEY_TTL,
            )
            pipe.set(
                SessionManager.SESSIONS.format(id=session.id),
                json.dumps(session.to_dict()),
            )
            pipe.execute()
