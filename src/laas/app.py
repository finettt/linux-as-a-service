from functools import wraps
import os
from flask import Flask, jsonify, request
from src.laas.session_manager import SessionManager
from redis import Redis
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
redis = Redis("redis",6379,0,username=os.getenv("REDIS_USER"), password=os.getenv("REDIS_USER_PASSWORD"))
session_mgr = SessionManager(redis_client=redis)

def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401

        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Invalid Authorization header format"}), 401

        jwt_token = auth_header.split(' ')[1]
        session = session_mgr.find_session_by_token(token=jwt_token)
        if session is None:
            return jsonify({"error": "Invalid authentication token"}), 401

        res = session_mgr.auth_session(session_id=session.id, encoded_jwt=jwt_token)
        if "error" in res:
            return jsonify({"error": "Authentication failed"}), 401

        kwargs['session_id'] = session.id
        return func(*args, **kwargs)

    return wrapper

@app.post("/linux/")
@app.get("/linux/")
@auth_required
def command(session_id):
    if request.method == "POST":
        data = request.get_json()
        user_input = data.get("command", "").strip()


        if not user_input:
            return jsonify({"error": "No command provided"}), 400
        
        session = session_mgr.find_session_by_id(session_id)
        result = session.execute_command(user_input)
        return jsonify(result)
    elif request.method == "GET":
        session = session_mgr.find_session_by_id(session_id)
        return jsonify({"id":session.id,"pwd": session.get_pwd(), "history": session.history})

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
        return jsonify(session_mgr.register_session(session_id=session_id,username=username,hex_cipher=hex_cipher))
    

@app.get("/debug/sessions")
def debug_1():
    return jsonify({
        "session_c": session_mgr.get_session_c(),
        "sessions": session_mgr.get_sessions()
    })