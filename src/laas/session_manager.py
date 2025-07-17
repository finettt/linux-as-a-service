import json
import logging
from typing import Dict, Optional, Union
from src.laas.exceptions.AnotherKeyError import AnotherKeyError
from src.laas.session import Session
import redis
import rsa

# BUG: Неправильная инициализация логгера - нужно использовать logging.getLogger()
logger = logging.getLogger("my_logger")


class SessionManager:
    SESSION_COUNTER = "laas:sessions:counter"
    SESSIONS = "laas:session:{id}"
    TOKENS = "laas:token:{token}"
    PRIVATE_KEYS = "laas:private_key:{id}"
    PRIVATE_KEY_TTL = 300
    # BUG: RSA ключ 512 бит крайне небезопасен, минимум 2048 (как указано в FIXME)
    RSA_KEY_SIZE = 512  # FIXME: Increase RSA key to 2048

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def get_free_id(self) -> int:
        # BUG: Потенциальная race condition - между получением ID и созданием сессии
        # другой процесс может использовать тот же ID
        next_id = self.redis.incr(SessionManager.SESSION_COUNTER)
        return next_id

    def request_session(self) -> Dict[str, Union[int, Dict[str, int]]]:
        free_id = self.get_free_id()
        new_session = Session(id=free_id)
        (publicKey, privateKey) = rsa.newkeys(SessionManager.RSA_KEY_SIZE)
        new_session.set_rsa_private(privateKey)
        self.__append_session(new_session)
        publicKey_json = {"n": publicKey.n, "e": publicKey.e}
        return {"id": free_id, "pubKey": publicKey_json}

    def __delete_session(self, session: Session):
        token = session.get_token()
        if token:
            self.redis.delete(SessionManager.TOKENS.format(token=token))
        self.redis.delete(SessionManager.SESSIONS.format(id=session.id))
        # BUG: Не удаляется приватный ключ из PRIVATE_KEYS
        return True

    def register_session(self, session_id: int, username: str, hex_cipher: str):
        session_dump: Session = self.find_session_by_id(int(session_id))
        if session_dump is not None:
            session = session_dump
            try:
                secret_key = session.decrypt_password(hex_cipher=hex_cipher)
            except AnotherKeyError as e:
                return {"error": f"Invalid cipher: {str(e)}"}

            session.set_secret_key(secret_key=secret_key)

            data = {
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

    def auth_session(self, session_id: int, encoded_jwt: str):
        session_dump = self.find_session_by_id(session_id)

        if session_dump is not None:
            session: Session = session_dump
            val_result = session.validate(encoded_jwt)
            if val_result.get("val") == "Session validation success!":
                return {"auth": "Session auth success!"}
            elif val_result.get("error") == "Session has expired!":
                self.__delete_session(session)
                # BUG: Нет return после удаления сессии - код продолжит выполнение
            else:
                return val_result
        else:
            return {
                "error": f"Session {session_id} does not exist!",
            }

    def find_session_by_id(self, id: int) -> Optional[Session]:
        session_dump = self.redis.get(SessionManager.SESSIONS.format(id=id))
        if not session_dump:
            return None

        try:
            session_data = json.loads(session_dump)
            if self.redis.get(SessionManager.PRIVATE_KEYS.format(id=id)):
                rsa_private = json.loads(
                    self.redis.get(SessionManager.PRIVATE_KEYS.format(id=id))
                )
                rsa_private = rsa.PrivateKey(
                    rsa_private["n"],
                    rsa_private["e"],
                    rsa_private["d"],
                    rsa_private["p"],
                    rsa_private["q"],
                )
            else:
                rsa_private = None
            session = Session(0)
            session.from_dict(session_dict=session_data, rsa_private=rsa_private)
            return session
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            # Log the error if you have logging set up
            logger.error(f"Failed to deserialize session {id}: {e}")
            return None

    def find_session_by_token(self, token: str) -> Optional[Session]:
        session_id = int(self.redis.get(SessionManager.TOKENS.format(token=token)))
        if session_id:
            # BUG: session_id из Redis приходит как bytes, нужно декодировать
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
