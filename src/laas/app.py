from functools import wraps
from flask import Flask, abort, jsonify, request

from src.laas.session_manager import SessionManager


app = Flask(__name__)
session_mgr = SessionManager()

def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        data = request.get_json()
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401

        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Invalid Authorization header format"}), 401

        jwt_token = auth_header.split(' ')[1]
        if not data:
            return jsonify({"error": "Invalid or empty JSON body."}), 400
        else:
            s_id = session_mgr.__find_session_by_token(token=jwt_token)
            if s_id==None:
                return jsonify({"error":"Session does not exists with your token"}), 400
            else:
                res = session_mgr.auth_session(session_id=s_id,jwt=jwt_token)
                if "error" in res:
                    return jsonify({"error":"Authentication failed."}), 401
                else:
                    kwargs['session_id'] = s_id
                    result = func(*args, **kwargs)
        return result
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
        
        session = session_mgr.__find_session_by_id(session_id)
        result = session.execute_command(user_input)
        return jsonify(result)
    elif request.method == "GET":
        session = session_mgr.__find_session_by_id(session_id)
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
    if session_id==None or username==None:
        return jsonify({"error":str(f"Bad data: s_id:{session_id}, username:{username}, hex_cipher:{hex_cipher}")}), 400
    else:
        return jsonify(session_mgr.register_session(session_id=session_id,username=username,hex_cipher=hex_cipher))