import eventlet
eventlet.monkey_patch()

import telnetlib
import logging
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from openai import OpenAI
# 设置日志级别
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# 存储每个 SocketIO 连接对应的 Telnet 对象，key 为 SocketIO 连接 ID
connections = {}

def telnet_connect(sid, host, port):
    """尝试通过 Telnet 连接远程设备（无用户名密码认证）"""
    try:
        logging.info(f"[{sid}] 尝试连接到设备 {host}:{port}")
        tn = telnetlib.Telnet(host, port, timeout=10)
        connections[sid] = tn

        # 启动后台任务监听设备输出
        socketio.start_background_task(telnet_listen, sid, tn)

        socketio.emit('ssh_output', {'data': "成功连接到设备.\n"}, room=sid)
    except Exception as e:
        error_msg = f"连接错误: {str(e)}"
        logging.error(f"[{sid}] {error_msg}")
        socketio.emit('ssh_output', {'data': error_msg + "\n"}, room=sid)

def telnet_listen(sid, tn):
    """持续监听 Telnet 输出，并将数据通过 SocketIO 发送到前端"""
    try:
        while True:
            data = tn.read_very_eager().decode(errors="ignore")
            if data:
                logging.debug(f"[{sid}] 收到设备数据: {data}")
                socketio.emit('ssh_output', {'data': data}, room=sid)
            eventlet.sleep(0.1)
    except Exception as e:
        error_msg = f"连接断开: {str(e)}"
        logging.error(f"[{sid}] {error_msg}")
        socketio.emit('ssh_output', {'data': error_msg + "\n"}, room=sid)
    finally:
        try:
            tn.close()
        except Exception:
            pass
        if sid in connections:
            del connections[sid]
        logging.info(f"[{sid}] Telnet 连接已关闭。")

@socketio.on('connect_device')
def handle_connect_device(data):
    """处理前端发起的设备连接请求"""
    sid = request.sid
    ip = data.get('ip')
    try:
        port = int(data.get('port', 23))
    except ValueError:
        port = 23
    logging.info(f"[{sid}] 收到连接请求: IP={ip} 端口={port}")
    socketio.start_background_task(telnet_connect, sid, ip, port)

@socketio.on('ssh_input')
def handle_ssh_input(data):
    """接收前端终端输入的命令，并通过 Telnet 发送到设备"""
    sid = request.sid
    cmd = data.get('cmd', '')
    if sid in connections:
        tn = connections[sid]
        try:
            logging.info(f"[{sid}] 发送命令: {cmd}")
            tn.write(cmd.encode('utf-8') + b"\n")
            socketio.emit('ssh_output', {'data': f"执行命令: {cmd}\n"}, room=sid)
        except Exception as e:
            error_msg = f"命令发送错误: {str(e)}"
            logging.error(f"[{sid}] {error_msg}")
            socketio.emit('ssh_output', {'data': error_msg + "\n"}, room=sid)
    else:
        error_msg = "错误: 未连接到设备\n"
        logging.warning(f"[{sid}] {error_msg.strip()}")
        socketio.emit('ssh_output', {'data': error_msg}, room=sid)


@socketio.on('chat_message')
def handle_chat_message(data):
    """处理右侧聊天框发送的消息（示例回复）"""
    sid = request.sid
    message = data.get('message', ' ')  # message是用户发送到后端的信息

    # Prepare the message to send to the AI
    from openai import OpenAI
    client = OpenAI(api_key="<你的apikey>", base_url="https://api.deepseek.com")
    reply = [
        {"role": "system", "content": "You are a helpful assistant."}
    ]
    reply.append({"role": "user", "content": message})

    # Call the AI model to get the reply
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=reply,
        stream=True
    )

    # Collect the AI response
    ai_reply = ""
    for chunk in response:
        if chunk.choices[0].delta.content:
            ai_reply += chunk.choices[0].delta.content

    # Log the messages
    logging.info(f"[{sid}] 聊天消息: {message}，回复: {ai_reply}")

    # Emit the AI's reply back to the frontend
    emit('chat_reply', {'reply': ai_reply}, room=sid)


@socketio.on('disconnect')
def handle_disconnect():
    """处理客户端断开连接，清理对应的 Telnet 连接"""
    sid = request.sid
    if sid in connections:
        try:
            connections[sid].close()
        except Exception:
            pass
        del connections[sid]
    logging.info(f"[{sid}] 客户端已断开连接。")

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
