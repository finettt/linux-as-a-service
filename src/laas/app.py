from functools import wraps
from typing import Dict, Optional
from flask import Flask, jsonify, request
from src.laas.session import Session
from src.laas.session_manager import SessionManager
from src.laas.cfgloader import CfgLoader
from redis import Redis

config = CfgLoader("/app/config.yaml")
config.load_config()

app = Flask(__name__)
redis = Redis(
    config.get("database.host"),
    config.get("database.port"),
    config.get("database.database"),
    username=config.get("database.user"),
    password=config.get("database.password"),
)
session_mgr = SessionManager(redis_client=redis)


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Invalid Authorization header format"}), 401

        jwt_token = auth_header.split(" ")[1]
        session: Optional[Session] = session_mgr.find_session_by_token(token=jwt_token)
        if session is None:
            return jsonify({"error": "Invalid authentication token"}), 401

        res = session_mgr.auth_session(
            session_id=str(session.id), encoded_jwt=jwt_token
        )
        if "error" in res:
            return jsonify({"error": "Authentication failed"}), 401

        kwargs["session_id"] = session.id
        return func(*args, **kwargs)

    return wrapper


@app.post("/linux/")
@app.get("/linux/")
@auth_required
def command(session_id):
    if request.method == "POST":
        data: Dict = request.get_json()
        user_input = str(data.get("command", "").strip())

        if not user_input:
            return jsonify({"error": "No command provided"}), 400

        session: Optional[Session] = session_mgr.find_session_by_id(session_id)
        if session is None:
            return jsonify({"error": "session not found!"})

        result: str = session.execute_command(user_input)
        return jsonify(result)
    elif request.method == "GET":
        session: Optional[Session] = session_mgr.find_session_by_id(session_id)
        if session is None:
            return jsonify({"error": "session not found!"})
        return jsonify(
            {
                "id": session.id,
                "pwd": session.get_pwd(),
                "history": session.history,
            }
        )


@app.get("/auth/new")
def new_client():
    return jsonify(session_mgr.request_session())


@app.post("/auth/complete")
def create_client():
    data = request.get_json()
    session_id = data.get("id", None)
    username = data.get("username", None)
    hex_cipher = data.get("hex_cipher", None)
    if session_id is None or username is None:
        return jsonify({"error": "Missing required parameters: id or username"}), 400
    else:
        return jsonify(
            session_mgr.register_session(
                session_id=session_id, username=username, hex_cipher=hex_cipher
            )
        )
