# server.py - Ứng dụng nhắn tin an toàn qua WebSocket với xác thực và tin nhắn riêng tư
import asyncio
import websockets
import json
from datetime import datetime
import collections
import hashlib
import os # Thêm import os để kiểm tra sự tồn tại của file

# --- Cấu hình người dùng (tải từ file, trong thực tế sẽ dùng DB) ---
USERS_FILE = "users.json"
USERS = {} # Sẽ được tải từ file

# Hàm để tải người dùng từ file JSON
def load_users():
    global USERS
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            USERS = json.load(f)
        print(f"Đã tải {len(USERS)} người dùng từ {USERS_FILE}")
    else:
        # Nếu file không tồn tại, khởi tạo một dictionary rỗng và lưu lại
        USERS = {}
        save_users() # Lưu lại ngay lập tức một file users.json rỗng
        print(f"File {USERS_FILE} không tồn tại. Đã tạo file mới rỗng.")

# Hàm để lưu người dùng vào file JSON
def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(USERS, f, indent=4)
    print(f"Đã lưu {len(USERS)} người dùng vào {USERS_FILE}")

# Lưu trữ các kết nối WebSocket đang hoạt động và thông tin người dùng
# key: websocket_object, value: {"username": "...", "authenticated": True, "websocket": websocket_object}
connected_clients = {}

# Lịch sử tin nhắn và tệp (đã mã hóa)
# Mỗi entry sẽ có type: "text" hoặc "file"
# Đối với tệp, chỉ lưu metadata trong history (không lưu nội dung để tránh tốn RAM)
message_history = collections.deque(maxlen=100) # Giới hạn 100 tin nhắn/tệp gần nhất

# Hàm băm mật khẩu
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Hàm thông báo danh sách người dùng online đến tất cả các client đã xác thực
async def notify_users_list():
    online_users = [info["username"] for info in connected_clients.values() if info.get("authenticated")]
    message = json.dumps({"type": "user_list", "users": online_users})
    for client_info in list(connected_clients.values()):
        if client_info.get("authenticated"):
            try:
                await client_info["websocket"].send(message)
            except websockets.ConnectionClosed:
                print(f"Failed to send user list to {client_info['username']}: Connection closed")
            except Exception as e:
                print(f"Error sending user list to {client_info['username']}: {e}")

async def register_client(websocket):
    connected_clients[websocket] = {"authenticated": False, "username": None, "websocket": websocket}
    print(f"Client mới kết nối từ {websocket.remote_address}. Tổng số: {len(connected_clients)}")

async def unregister_client(websocket):
    if websocket in connected_clients:
        username = connected_clients[websocket].get("username")
        del connected_clients[websocket]
        print(f"Client {username if username else websocket.remote_address} đã ngắt kết nối. Tổng số: {len(connected_clients)}")
        if username:
            await notify_users_list() # Cập nhật danh sách online khi có người ngắt kết nối

async def handler(websocket):
    await register_client(websocket)
    client_authenticated = False
    client_username = None

    try:
        async for message in websocket:
            data = json.loads(message)
            print(f"Nhận từ {websocket.remote_address}: {data}")

            # Xử lý xác thực/đăng ký trước tiên
            if data["type"] == "authenticate":
                username = data.get("username")
                password = data.get("password")
                hashed_password = hash_password(password)
                if username in USERS and USERS[username] == hashed_password:
                    # Kiểm tra xem người dùng đã online chưa
                    is_online = False
                    for client_ws, client_info in connected_clients.items():
                        if client_ws != websocket and client_info.get("username") == username and client_info.get("authenticated"):
                            is_online = True
                            break

                    if is_online:
                        await websocket.send(json.dumps({"type": "auth_fail", "message": "Người dùng đã online."}))
                        print(f"Đăng nhập thất bại cho {username}: Đã online.")
                    else:
                        connected_clients[websocket]["authenticated"] = True
                        connected_clients[websocket]["username"] = username
                        client_authenticated = True
                        client_username = username
                        await websocket.send(json.dumps({"type": "auth_success"}))
                        print(f"Người dùng {username} đã đăng nhập thành công.")
                        await notify_users_list()
                else:
                    await websocket.send(json.dumps({"type": "auth_fail", "message": "Tên người dùng hoặc mật khẩu không đúng."}))
                    print(f"Đăng nhập thất bại cho {username}.")
                continue # Tiếp tục vòng lặp để chờ tin nhắn tiếp theo

            elif data["type"] == "register": # <-- THÊM ĐOẠN XỬ LÝ ĐĂNG KÝ MỚI
                username = data.get("username")
                password = data.get("password")
                if not username or not password:
                    await websocket.send(json.dumps({"type": "register_fail", "message": "Tên người dùng và mật khẩu không được trống."}))
                    continue
                if username in USERS:
                    await websocket.send(json.dumps({"type": "register_fail", "message": "Tên người dùng đã tồn tại."}))
                else:
                    USERS[username] = hash_password(password)
                    save_users() # <-- Lưu lại USERS sau khi đăng ký thành công
                    await websocket.send(json.dumps({"type": "register_success", "message": "Đăng ký thành công."}))
                    print(f"Người dùng mới đã đăng ký: {username}")
                continue # Tiếp tục vòng lặp

            # Yêu cầu xác thực cho các hành động khác
            if not client_authenticated:
                await websocket.send(json.dumps({"type": "error", "message": "Chưa xác thực."}))
                continue

            if data["type"] == "logout":
                connected_clients[websocket]["authenticated"] = False
                connected_clients[websocket]["username"] = None
                client_authenticated = False
                client_username = None
                await websocket.send(json.dumps({"type": "logout_success", "message": "Đăng xuất thành công."}))
                await notify_users_list()
                break # Thoát vòng lặp async for, chuyển đến finally

            elif data["type"] == "get_history":
                recipient_filter = data.get("recipient", "all")
                # Lọc lịch sử theo người nhận (hoặc chat chung)
                filtered_history = []
                for msg in message_history:
                    # Nếu là tin nhắn chat chung
                    if msg.get("recipient") == "all" and recipient_filter == "all":
                        filtered_history.append(msg)
                    # Nếu là tin nhắn riêng tư
                    elif msg.get("recipient") != "all":
                        # msg.sender -> msg.recipient (tin nhắn gửi đi)
                        # msg.recipient -> msg.sender (tin nhắn nhận về)
                        if (msg.get("sender") == client_username and msg.get("recipient") == recipient_filter) or \
                           (msg.get("recipient") == client_username and msg.get("sender") == recipient_filter):
                            filtered_history.append(msg)
                await websocket.send(json.dumps({"type": "history", "messages": list(filtered_history)}))

            elif data["type"] == "send_message":
                encrypted_msg_b64 = data.get("encrypted_msg")
                iv_b64 = data.get("iv")
                recipient = data.get("recipient", "all") # Mặc định là "all" (chat chung)

                if encrypted_msg_b64 and iv_b64:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    message_data = {
                        "type": "new_message",
                        "sender": client_username,
                        "encrypted_msg": encrypted_msg_b64,
                        "iv": iv_b64,
                        "timestamp": timestamp,
                        "recipient": recipient
                    }

                    if recipient == "all":
                        message_history.append({"type": "text", **message_data}) # Lưu vào lịch sử
                        await broadcast_message(message_data)
                    else:
                        # Gửi tin nhắn riêng tư
                        await websocket.send(json.dumps(message_data)) # Gửi lại cho người gửi để hiển thị
                        found_recipient = False
                        for client_ws, client_info in list(connected_clients.items()):
                            if client_info.get("username") == recipient and client_info.get("authenticated") and client_ws != websocket:
                                try:
                                    await client_ws.send(json.dumps(message_data))
                                    found_recipient = True
                                    print(f"Tin nhắn riêng tư từ {client_username} đến {recipient} đã gửi.")
                                except websockets.ConnectionClosed:
                                    print(f"Người nhận {recipient} đã ngắt kết nối.")
                        if not found_recipient:
                            await websocket.send(json.dumps({"type": "error", "message": f"Người dùng '{recipient}' không online hoặc không tồn tại."}))
                            print(f"Tin nhắn riêng tư từ {client_username} đến {recipient} không gửi được (người nhận không online).")

                else:
                    await websocket.send(json.dumps({"type": "error", "message": "Tin nhắn hoặc IV trống!"}))

            elif data["type"] == "send_file": # New message type for files
                encrypted_filename_b64 = data.get("encrypted_filename")
                iv_filename_b64 = data.get("iv_filename")
                encrypted_file_content_b64 = data.get("encrypted_file_content")
                iv_file_content_b64 = data.get("iv_file_content")
                file_type = data.get("file_type")
                recipient = data.get("recipient", "all")

                if all([encrypted_filename_b64, iv_filename_b64, encrypted_file_content_b64, iv_file_content_b64, file_type]):
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    file_data = {
                        "type": "new_file", # Indicate it's a file
                        "sender": client_username,
                        "encrypted_filename": encrypted_filename_b64,
                        "iv_filename": iv_filename_b64,
                        "encrypted_file_content": encrypted_file_content_b64, # Keep encrypted and Base64
                        "iv_file_content": iv_file_content_b64,
                        "file_type": file_type,
                        "timestamp": timestamp,
                        "recipient": recipient
                    }

                    if recipient == "all":
                        # For general chat history, only store metadata if file content is large
                        message_history.append({
                            "type": "file",
                            "sender": client_username,
                            "encrypted_filename": encrypted_filename_b64,
                            "iv_filename": iv_filename_b64,
                            "file_type": file_type,
                            "timestamp": timestamp,
                            "recipient": recipient
                            # Note: encrypted_file_content is NOT stored in history to avoid large memory use
                            # Re-downloading from history would require server-side file storage
                        })
                        await broadcast_message(file_data) # Broadcast the full file data
                    else:
                        # Private file sending
                        await websocket.send(json.dumps(file_data)) # Send to sender themselves
                        found_recipient = False
                        for client_ws, client_info in list(connected_clients.items()):
                            if client_info.get("username") == recipient and client_info.get("authenticated") and client_ws != websocket:
                                try:
                                    await client_ws.send(json.dumps(file_data))
                                    found_recipient = True
                                    print(f"Tệp riêng tư từ {client_username} đến {recipient} đã gửi.")
                                except websockets.ConnectionClosed:
                                    print(f"Người nhận tệp {recipient} đã ngắt kết nối.")
                        if not found_recipient:
                            await websocket.send(json.dumps({"type": "error", "message": f"Người dùng '{recipient}' không online hoặc không tồn tại."}))
                            print(f"Tệp riêng tư từ {client_username} đến {recipient} không gửi được (người nhận không online).")

                else:
                    await websocket.send(json.dumps({"type": "error", "message": "Dữ liệu tệp hoặc IV trống!"}))

            else:
                await websocket.send(json.dumps({"type": "error", "message": "Hành động không xác định."}))

    except websockets.exceptions.ConnectionClosedOK:
        print(f"Client {client_username if client_username else websocket.remote_address} đã đóng kết nối bình thường.")
    except json.JSONDecodeError:
        print(f"Received invalid JSON from {websocket.remote_address}")
        await websocket.send(json.dumps({"type": "error", "message": "Dữ liệu JSON không hợp lệ."}))
    except Exception as e:
        print(f"Error handling client {websocket.remote_address}: {e}")
        # Không gửi lỗi chi tiết ra client trong môi trường thật
        await websocket.send(json.dumps({"type": "error", "message": "Lỗi server nội bộ."}))
    finally:
        await unregister_client(websocket)

async def broadcast_message(message_data):
    """Gửi tin nhắn (chung) hoặc tệp (chung) đến tất cả các client đã xác thực."""
    for client_info in list(connected_clients.values()):
        if client_info.get("authenticated"):
            try:
                await client_info["websocket"].send(json.dumps(message_data))
            except websockets.ConnectionClosed:
                print(f"Failed to send broadcast to {client_info['username']}: Connection closed")
            except Exception as e:
                print(f"Error broadcasting to {client_info['username']}: {e}")

async def main():
    load_users() # <-- Tải người dùng khi server khởi động
    print("Bắt đầu Server nhắn tin an toàn với xác thực và tin nhắn riêng tư trên ws://localhost:8080")
    async with websockets.serve(handler, "localhost", 8080):
        await asyncio.Future()  # Chạy mãi mãi

if __name__ == "__main__":
    asyncio.run(main())