from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date, timedelta
import sqlite3
import json
from jose import jwt
from passlib.context import CryptContext

# --- Конфигурация ---
SECRET_KEY = "supersecretkey_sirius2026"
# /|\ ВНИМАНИЕ: В реальном проекте ключ я хранил в .env, а не в коде!
#  |
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Сириус.Аренда API", version="2.0")
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Модели данных ---
class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class RoomCreate(BaseModel):
    name: str
    capacity: int
    equipment: List[str] = []

class Room(RoomCreate):
    id: int

class BookingCreate(BaseModel):
    room_id: int
    start_time: datetime
    end_time: datetime

class Booking(BookingCreate):
    id: int
    user_name: str
    status: str = "active"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str

# --- Инициализация БД ---
def init_db():
    conn = sqlite3.connect("sirius.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            equipment TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (room_id) REFERENCES rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    # Создаём администратора по умолчанию
    admin_exists = c.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        hashed = pwd_context.hash("admin123")
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("admin", hashed, "admin"))
    conn.commit()
    conn.close()

init_db()

# --- Вспомогательные функции ---
def get_db():
    conn = sqlite3.connect("sirius.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_username(username: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Неверный или просроченный токен")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Неверный токен")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user

def get_current_admin(user = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return user

def room_to_dict(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "capacity": row["capacity"],
        "equipment": json.loads(row["equipment"]) if row["equipment"] else []
    }

def booking_to_dict(row):
    return {
        "id": row["id"],
        "room_id": row["room_id"],
        "user_name": row["user_name"],
        "start_time": row["start_time"],
        "end_time": row["end_time"],
        "status": row["status"]
    }

# --- Эндпоинты аутентификации ---
@app.post("/register", response_model=TokenResponse)
def register(user: UserRegister):
    if get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    
    hashed = pwd_context.hash(user.password)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
              (user.username, hashed))
    conn.commit()
    conn.close()
    
    token = create_access_token({"sub": user.username, "role": "user"})
    return {"access_token": token, "token_type": "bearer", "username": user.username}

@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin):
    db_user = get_user_by_username(user.username)
    if not db_user:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    
    if not pwd_context.verify(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    
    token = create_access_token({"sub": db_user["username"], "role": db_user["role"]})
    return {"access_token": token, "token_type": "bearer", "username": db_user["username"]}

# --- Защищённые эндпоинты для комнат ---
@app.post("/rooms", response_model=Room, status_code=201)
def create_room(room: RoomCreate, current_user = Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    equipment_json = json.dumps(room.equipment)
    c.execute("INSERT INTO rooms (name, capacity, equipment) VALUES (?, ?, ?)",
              (room.name, room.capacity, equipment_json))
    conn.commit()
    room_id = c.lastrowid
    conn.close()
    return {**room.model_dump(), "id": room_id}

@app.get("/rooms", response_model=List[Room])
def get_rooms(capacity: Optional[int] = None, equipment: Optional[str] = None):
    conn = get_db()
    c = conn.cursor()
    query = "SELECT * FROM rooms"
    params = []
    conditions = []
    if capacity:
        conditions.append("capacity >= ?")
        params.append(capacity)
    if equipment:
        conditions.append("equipment LIKE ?")
        params.append(f"%{equipment}%")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return [room_to_dict(row) for row in rows]

@app.get("/rooms/{room_id}", response_model=Room)
def get_room(room_id: int):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM rooms WHERE id = ?", (room_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Комната не найдена")
    return room_to_dict(row)

@app.put("/rooms/{room_id}", response_model=Room)
def update_room(room_id: int, room: RoomCreate, current_user = Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM rooms WHERE id = ?", (room_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Комната не найдена")
    equipment_json = json.dumps(room.equipment)
    c.execute("UPDATE rooms SET name = ?, capacity = ?, equipment = ? WHERE id = ?",
              (room.name, room.capacity, equipment_json, room_id))
    conn.commit()
    conn.close()
    return {**room.model_dump(), "id": room_id}

@app.delete("/rooms/{room_id}", status_code=204)
def delete_room(room_id: int, current_user = Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM rooms WHERE id = ?", (room_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Комната не найдена")
    c.execute("DELETE FROM bookings WHERE room_id = ?", (room_id,))
    c.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
    conn.commit()
    conn.close()
    return

# --- Защищённые эндпоинты для бронирований ---
@app.post("/bookings", response_model=Booking, status_code=201)
def create_booking(booking: BookingCreate, current_user = Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT id FROM rooms WHERE id = ?", (booking.room_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Комната не найдена")
    
    if booking.start_time >= booking.end_time:
        conn.close()
        raise HTTPException(
            status_code=400, 
            detail="Время начала должно быть раньше времени окончания"
        )
    
    c.execute("""
        SELECT id FROM bookings 
        WHERE room_id = ? 
        AND status = 'active'
        AND (
            (start_time <= ? AND end_time > ?) OR
            (start_time < ? AND end_time >= ?) OR
            (start_time >= ? AND end_time <= ?)
        )
    """, (
        booking.room_id,
        booking.start_time.isoformat(), booking.start_time.isoformat(),
        booking.end_time.isoformat(), booking.end_time.isoformat(),
        booking.start_time.isoformat(), booking.end_time.isoformat()
    ))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Комната уже занята на это время")
    
    c.execute(
        "INSERT INTO bookings (room_id, user_id, start_time, end_time) VALUES (?, ?, ?, ?)",
        (booking.room_id, current_user["id"], booking.start_time.isoformat(), booking.end_time.isoformat())
    )
    conn.commit()
    booking_id = c.lastrowid
    conn.close()
    return {
        **booking.model_dump(),
        "id": booking_id,
        "user_name": current_user["username"],
        "status": "active"
    }

@app.delete("/bookings/{booking_id}", status_code=204)
def cancel_booking(booking_id: int, current_user = Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, user_id FROM bookings WHERE id = ?", (booking_id,))
    booking = c.fetchone()
    if not booking:
        conn.close()
        raise HTTPException(status_code=404, detail="Бронирование не найдено")
    
    if booking["user_id"] != current_user["id"] and current_user["role"] != "admin":
        conn.close()
        raise HTTPException(status_code=403, detail="Нельзя отменить чужое бронирование")
    
    c.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
    conn.commit()
    conn.close()
    return

@app.get("/rooms/{room_id}/bookings")
def get_room_bookings(room_id: int, date: date):
    conn = get_db()
    c = conn.cursor()
    start_date = date.isoformat()
    end_date = (datetime.combine(date, datetime.max.time())).isoformat()
    c.execute("""
        SELECT bookings.*, users.username as user_name 
        FROM bookings 
        JOIN users ON bookings.user_id = users.id
        WHERE room_id = ? 
        AND bookings.status = 'active'
        AND start_time >= ? 
        AND start_time <= ?
    """, (room_id, start_date, end_date))
    rows = c.fetchall()
    conn.close()
    return [booking_to_dict(row) for row in rows]

# --- Главная страница с интерфейсом ---
@app.get("/", response_class=HTMLResponse)
def get_index():
    return """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Сириус.Аренда</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; background: linear-gradient(135deg, #e8f0fe 0%, #d4e4f7 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #0b1a3a 0%, #1a3a7a 50%, #2a5aaa 100%); color: white; padding: 30px 40px; border-radius: 20px; margin-bottom: 30px; box-shadow: 0 10px 40px rgba(26, 58, 122, 0.3); position: relative; overflow: hidden; }
        .header::before { content: ''; position: absolute; top: -50%; right: -20%; width: 400px; height: 400px; background: rgba(255, 255, 255, 0.05); border-radius: 50%; pointer-events: none; }
        .header h1 { font-size: 2.2em; font-weight: 700; display: flex; align-items: center; gap: 15px; position: relative; z-index: 1; }
        .header h1 i { font-size: 1.2em; background: rgba(255, 255, 255, 0.15); padding: 12px; border-radius: 12px; }
        .header p { opacity: 0.85; margin-top: 8px; font-size: 1.1em; position: relative; z-index: 1; }
        .card { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 16px; padding: 25px 30px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06); margin-bottom: 25px; border: 1px solid rgba(255, 255, 255, 0.7); transition: transform 0.2s, box-shadow 0.2s; }
        .card:hover { box-shadow: 0 8px 30px rgba(0, 0, 0, 0.1); }
        .card h2, .card h3 { color: #0b1a3a; font-weight: 600; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        .card h2 i, .card h3 i { color: #1a3a7a; }
        .auth-form { max-width: 420px; margin: 40px auto; padding: 35px 40px; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1); }
        .auth-form h2 { text-align: center; color: #0b1a3a; margin-bottom: 20px; }
        .auth-form input { width: 100%; padding: 14px 16px; margin: 10px 0; border: 2px solid #e2e8f0; border-radius: 12px; font-size: 16px; transition: border 0.2s; background: #f8fafc; }
        .auth-form input:focus { border-color: #1a3a7a; outline: none; background: white; }
        .auth-form button { width: 100%; padding: 14px; background: linear-gradient(135deg, #1a3a7a, #2a5aaa); color: white; border: none; border-radius: 12px; font-size: 18px; font-weight: 600; cursor: pointer; transition: transform 0.15s, box-shadow 0.2s; margin-top: 10px; }
        .auth-form button:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(26, 58, 122, 0.3); }
        .auth-form .switch { text-align: center; margin-top: 15px; color: #1a3a7a; cursor: pointer; font-weight: 500; }
        .auth-form .switch:hover { text-decoration: underline; }
        .hidden { display: none !important; }
        #userInfo { display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: linear-gradient(135deg, #e8f5e9, #c8e6c9); border-radius: 12px; margin-bottom: 25px; }
        #userInfo span { font-size: 1.05em; color: #1e3a5f; }
        #userInfo span strong { color: #0b1a3a; }
        #logoutBtn { background: #dc3545; color: white; border: none; padding: 8px 20px; border-radius: 8px; cursor: pointer; font-weight: 500; transition: background 0.2s; }
        #logoutBtn:hover { background: #c82333; }
        
        /* Поиск */
        .search-box { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
        .search-box input { flex: 1; padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 12px; font-size: 16px; background: white; transition: border 0.2s; min-width: 200px; }
        .search-box input:focus { border-color: #1a3a7a; outline: none; }
        .search-box button { padding: 12px 24px; background: #1a3a7a; color: white; border: none; border-radius: 12px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        .search-box button:hover { background: #2a5aaa; }
        .search-box .clear-btn { background: #6c757d; }
        .search-box .clear-btn:hover { background: #5a6268; }
        
        .room-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 20px; }
        .room-item { background: #f8fafc; padding: 18px 20px; border-radius: 12px; border-left: 5px solid #1a3a7a; transition: transform 0.15s, box-shadow 0.15s; }
        .room-item:hover { transform: translateY(-3px); box-shadow: 0 6px 20px rgba(0, 0, 0, 0.06); }
        .room-item h3 { color: #0b1a3a; font-size: 1.1em; margin-bottom: 6px; }
        .room-item .info { color: #4a5a6a; font-size: 0.9em; margin: 4px 0; }
        .room-item .info i { width: 20px; color: #1a3a7a; }
        .room-actions { display: flex; gap: 8px; margin-top: 10px; justify-content: flex-end; }
        .room-actions button { border: none; border-radius: 8px; padding: 6px 12px; cursor: pointer; font-size: 13px; transition: transform 0.15s; }
        .room-actions button:hover { transform: scale(1.05); }
        .room-actions .edit-btn { background: #ffc107; color: #212529; }
        .room-actions .delete-btn { background: #dc3545; color: white; }
        
        .booking-form { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; background: #f8fafc; padding: 20px; border-radius: 12px; margin-top: 5px; }
        .booking-form label { font-weight: 500; color: #1e3a5f; font-size: 0.9em; }
        .booking-form select, .booking-form input { padding: 10px 14px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 15px; background: white; transition: border 0.2s; }
        .booking-form select:focus, .booking-form input:focus { border-color: #1a3a7a; outline: none; }
        .booking-form button { padding: 10px 28px; background: linear-gradient(135deg, #28a745, #34ce57); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; transition: transform 0.15s, box-shadow 0.2s; }
        .booking-form button:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(40, 167, 69, 0.3); }
        
        .schedule-controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 15px; }
        .schedule-controls select, .schedule-controls input { padding: 10px 14px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 15px; background: white; }
        .schedule-controls button { padding: 10px 24px; background: linear-gradient(135deg, #17a2b8, #20c997); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; transition: transform 0.15s; }
        .schedule-controls button:hover { transform: translateY(-2px); }
        .schedule-item { display: flex; justify-content: space-between; align-items: center; background: #f8fafc; padding: 10px 16px; border-radius: 8px; margin: 6px 0; border-left: 4px solid #28a745; }
        .schedule-item .time { font-weight: 500; color: #0b1a3a; }
        .schedule-item .user { color: #4a5a6a; }
        .cancel-btn { background: #dc3545; color: white; border: none; padding: 5px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 500; transition: background 0.2s; }
        .cancel-btn:hover { background: #c82333; }
        
        .admin-panel { background: #fff3e0; border-radius: 16px; padding: 20px 25px; border: 2px dashed #ff9800; }
        .admin-panel h2 { color: #e65100; }
        .admin-panel h2 i { color: #ff9800; }
        .admin-controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
        .admin-controls input { padding: 10px 14px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 14px; background: white; flex: 1 1 150px; }
        .admin-controls button { padding: 10px 24px; background: linear-gradient(135deg, #ff9800, #ffb74d); color: white; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; transition: transform 0.15s; }
        .admin-controls button:hover { transform: translateY(-2px); }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }
        .stat-card { background: white; padding: 15px 20px; border-radius: 12px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .stat-card .number { font-size: 2em; font-weight: 700; color: #1a3a7a; }
        .stat-card .label { color: #6c7a8a; font-size: 0.9em; }
        
        .message { padding: 12px 18px; border-radius: 10px; margin: 10px 0; font-weight: 500; display: flex; align-items: center; gap: 10px; }
        .message.success { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }
        .message.error { background: #f8d7da; color: #721c24; border-left: 4px solid #dc3545; }
        .message.hidden { display: none; }
        .empty-state { color: #6c7a8a; text-align: center; padding: 20px; font-style: italic; }
        
        /* Модальное окно для редактирования */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; }
        .modal.active { display: flex; }
        .modal-content { background: white; padding: 30px; border-radius: 20px; max-width: 500px; width: 90%; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .modal-content h2 { color: #0b1a3a; margin-bottom: 20px; }
        .modal-content input { width: 100%; padding: 12px 16px; margin: 8px 0; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 16px; }
        .modal-content input:focus { border-color: #1a3a7a; outline: none; }
        .modal-actions { display: flex; gap: 10px; margin-top: 15px; justify-content: flex-end; }
        .modal-actions button { padding: 10px 24px; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; }
        .modal-actions .save-btn { background: #28a745; color: white; }
        .modal-actions .save-btn:hover { background: #218838; }
        .modal-actions .cancel-btn-modal { background: #6c757d; color: white; }
        .modal-actions .cancel-btn-modal:hover { background: #5a6268; }
        
        @media (max-width: 600px) {
            .header h1 { font-size: 1.5em; }
            .booking-form { flex-direction: column; }
            .schedule-controls { flex-direction: column; align-items: stretch; }
            .admin-controls { flex-direction: column; }
            .room-grid { grid-template-columns: 1fr; }
            .search-box { flex-direction: column; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1><i class="fas fa-building"></i> Сириус.Аренда</h1>
        <p><i class="fas fa-calendar-check"></i> Бронирование пространств Университета «Сириус»</p>
    </div>

    <!-- Форма входа/регистрации -->
    <div id="authSection" class="auth-form">
        <h2 id="authTitle"><i class="fas fa-sign-in-alt"></i> Вход</h2>
        <input type="text" id="username" placeholder="👤 Имя пользователя">
        <input type="password" id="password" placeholder="🔒 Пароль">
        <button id="authBtn"><i class="fas fa-arrow-right"></i> Войти</button>
        <div class="switch" id="switchAuth">Нет аккаунта? Зарегистрироваться</div>
        <div id="authMessage" class="message hidden"></div>
    </div>

    <!-- Основное приложение -->
    <div id="appSection" class="hidden">
        <div id="userInfo">
            <span><i class="fas fa-user-circle"></i> Добро пожаловать, <strong id="currentUser">User</strong>!</span>
            <button id="logoutBtn"><i class="fas fa-sign-out-alt"></i> Выйти</button>
        </div>

        <!-- Комнаты -->
        <div class="card">
            <h2><i class="fas fa-door-open"></i> Доступные комнаты</h2>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Поиск по названию, вместимости, оборудованию...">
                <button id="searchBtn"><i class="fas fa-search"></i> Найти</button>
                <button id="clearSearchBtn" class="clear-btn"><i class="fas fa-times"></i> Сбросить</button>
            </div>
            <div id="roomsList" class="room-grid"></div>
        </div>

        <!-- Бронирование -->
        <div class="card">
            <h3><i class="fas fa-calendar-plus"></i> Забронировать комнату</h3>
            <div class="booking-form" id="bookingForm">
                <div style="flex:1; min-width:150px;">
                    <label>Комната</label>
                    <select id="bookingRoomId" style="width:100%;"></select>
                </div>
                <div style="flex:1; min-width:150px;">
                    <label>Начало</label>
                    <input type="datetime-local" id="bookingStart" style="width:100%;">
                </div>
                <div style="flex:1; min-width:150px;">
                    <label>Конец</label>
                    <input type="datetime-local" id="bookingEnd" style="width:100%;">
                </div>
                <button id="bookingBtn"><i class="fas fa-check"></i> Забронировать</button>
            </div>
            <div id="bookingMessage" class="message hidden"></div>
        </div>

        <!-- Расписание -->
        <div class="card">
            <h3><i class="fas fa-clock"></i> Расписание</h3>
            <div class="schedule-controls">
                <select id="scheduleRoomId"></select>
                <input type="date" id="scheduleDate">
                <button id="scheduleBtn"><i class="fas fa-search"></i> Показать</button>
            </div>
            <div id="scheduleList"></div>
        </div>

        <!-- Админ-панель -->
        <div id="adminSection" class="card admin-panel hidden">
            <h2><i class="fas fa-tools"></i> Администрирование</h2>
            <div class="admin-controls">
                <input type="text" id="roomName" placeholder="🏷️ Название комнаты">
                <input type="number" id="roomCapacity" placeholder="👥 Вместимость">
                <input type="text" id="roomEquipment" placeholder="🛠 Оборудование (через запятую)">
                <button id="createRoomBtn"><i class="fas fa-plus"></i> Создать</button>
            </div>
            <div id="adminMessage" class="message hidden"></div>
            
            <!-- Статистика -->
            <h3 style="margin-top: 20px;"><i class="fas fa-chart-bar"></i> Статистика</h3>
            <div class="stats-grid" id="statsGrid">
                <div class="stat-card"><div class="number" id="statRooms">0</div><div class="label">Комнат</div></div>
                <div class="stat-card"><div class="number" id="statBookings">0</div><div class="label">Бронирований сегодня</div></div>
                <div class="stat-card"><div class="number" id="statAvgCapacity">0</div><div class="label">Средняя вместимость</div></div>
                <div class="stat-card"><div class="number" id="statTotalBookings">0</div><div class="label">Всего бронирований</div></div>
            </div>
        </div>
    </div>
</div>

<!-- Модальное окно редактирования -->
<div class="modal" id="editModal">
    <div class="modal-content">
        <h2><i class="fas fa-edit"></i> Редактировать комнату</h2>
        <input type="hidden" id="editRoomId">
        <input type="text" id="editName" placeholder="Название">
        <input type="number" id="editCapacity" placeholder="Вместимость">
        <input type="text" id="editEquipment" placeholder="Оборудование (через запятую)">
        <div class="modal-actions">
            <button class="cancel-btn-modal" onclick="closeEditModal()">Отмена</button>
            <button class="save-btn" onclick="saveEditRoom()"><i class="fas fa-save"></i> Сохранить</button>
        </div>
        <div id="editMessage" class="message hidden"></div>
    </div>
</div>

<script>
    // --- Глобальные переменные ---
    let token = localStorage.getItem('access_token');
    let currentUser = localStorage.getItem('username');
    let isAdmin = false;
    let allRooms = [];

    // --- DOM элементы ---
    const authSection = document.getElementById('authSection');
    const appSection = document.getElementById('appSection');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const authBtn = document.getElementById('authBtn');
    const authTitle = document.getElementById('authTitle');
    const switchAuth = document.getElementById('switchAuth');
    const authMessage = document.getElementById('authMessage');
    const currentUserSpan = document.getElementById('currentUser');
    const logoutBtn = document.getElementById('logoutBtn');
    const roomsList = document.getElementById('roomsList');
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const clearSearchBtn = document.getElementById('clearSearchBtn');
    const bookingRoomId = document.getElementById('bookingRoomId');
    const bookingStart = document.getElementById('bookingStart');
    const bookingEnd = document.getElementById('bookingEnd');
    const bookingBtn = document.getElementById('bookingBtn');
    const bookingMessage = document.getElementById('bookingMessage');
    const scheduleRoomId = document.getElementById('scheduleRoomId');
    const scheduleDate = document.getElementById('scheduleDate');
    const scheduleBtn = document.getElementById('scheduleBtn');
    const scheduleList = document.getElementById('scheduleList');
    const adminSection = document.getElementById('adminSection');
    const roomName = document.getElementById('roomName');
    const roomCapacity = document.getElementById('roomCapacity');
    const roomEquipment = document.getElementById('roomEquipment');
    const createRoomBtn = document.getElementById('createRoomBtn');
    const adminMessage = document.getElementById('adminMessage');
    const editModal = document.getElementById('editModal');
    const editRoomId = document.getElementById('editRoomId');
    const editName = document.getElementById('editName');
    const editCapacity = document.getElementById('editCapacity');
    const editEquipment = document.getElementById('editEquipment');
    const editMessage = document.getElementById('editMessage');
    const statRooms = document.getElementById('statRooms');
    const statBookings = document.getElementById('statBookings');
    const statAvgCapacity = document.getElementById('statAvgCapacity');
    const statTotalBookings = document.getElementById('statTotalBookings');

    let isLogin = true;

    // --- Функции API ---
    async function apiRequest(url, method = 'GET', body = null, auth = false) {
        const headers = { 'Content-Type': 'application/json' };
        if (auth && token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        const options = { method, headers };
        if (body) options.body = JSON.stringify(body);
        
        const response = await fetch(url, options);
        if (response.status === 401) {
            logout();
            throw new Error('Сессия истекла');
        }
        return response;
    }

    // --- Аутентификация ---
    async function authUser() {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        if (!username || !password) {
            showMessage(authMessage, 'Заполните все поля', 'error');
            return;
        }

        const endpoint = isLogin ? '/login' : '/register';
        try {
            const response = await apiRequest(endpoint, 'POST', { username, password });
            if (!response.ok) {
                const data = await response.json();
                showMessage(authMessage, data.detail || 'Ошибка', 'error');
                return;
            }
            const data = await response.json();
            token = data.access_token;
            currentUser = data.username;
            localStorage.setItem('access_token', token);
            localStorage.setItem('username', currentUser);
            showMessage(authMessage, '✅ Успешно!', 'success');
            setTimeout(() => loadApp(), 500);
        } catch (e) {
            showMessage(authMessage, 'Ошибка соединения', 'error');
        }
    }

    function logout() {
        token = null;
        currentUser = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('username');
        appSection.classList.add('hidden');
        authSection.classList.remove('hidden');
        authTitle.textContent = 'Вход';
        authBtn.textContent = 'Войти';
        isLogin = true;
        switchAuth.textContent = 'Нет аккаунта? Зарегистрироваться';
    }

    // --- Загрузка приложения ---
    async function loadApp() {
        authSection.classList.add('hidden');
        appSection.classList.remove('hidden');
        currentUserSpan.textContent = currentUser;
        
        if (currentUser === 'admin') {
            isAdmin = true;
            adminSection.classList.remove('hidden');
        } else {
            isAdmin = false;
            adminSection.classList.add('hidden');
        }

        await loadRooms();
        await loadBookingRooms();
        await loadScheduleRooms();
        await loadStats();
        
        const now = new Date();
        const defaultTime = new Date(now.getTime() + 60 * 60 * 1000);
        bookingStart.value = defaultTime.toISOString().slice(0, 16);
        bookingEnd.value = new Date(defaultTime.getTime() + 60 * 60 * 1000).toISOString().slice(0, 16);
        
        const today = new Date().toISOString().split('T')[0];
        scheduleDate.value = today;
        await loadSchedule();
    }

    // --- Комнаты ---
    async function loadRooms(filter = '') {
        try {
            let url = '/rooms';
            if (filter) {
                // Простая фильтрация на клиенте для демонстрации
                // В реальном проекте лучше делать на сервере
            }
            const response = await apiRequest(url);
            if (!response.ok) return;
            allRooms = await response.json();
            
            let filtered = allRooms;
            if (filter) {
                const f = filter.toLowerCase();
                filtered = allRooms.filter(r => 
                    r.name.toLowerCase().includes(f) ||
                    r.capacity.toString().includes(f) ||
                    r.equipment.join(' ').toLowerCase().includes(f)
                );
            }
            
            if (filtered.length === 0) {
                roomsList.innerHTML = '<div class="empty-state">📭 Ничего не найдено</div>';
                return;
            }
            roomsList.innerHTML = filtered.map(r => `
                <div class="room-item">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <h3><i class="fas fa-door-closed"></i> ${r.name}</h3>
                            <div class="info"><i class="fas fa-users"></i> Вместимость: ${r.capacity} чел.</div>
                            <div class="info"><i class="fas fa-tools"></i> ${r.equipment.join(', ') || 'Нет оборудования'}</div>
                        </div>
                        ${isAdmin ? `
                        <div class="room-actions">
                            <button class="edit-btn" onclick="openEditModal(${r.id})"><i class="fas fa-pen"></i></button>
                            <button class="delete-btn" onclick="deleteRoom(${r.id})"><i class="fas fa-trash"></i></button>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        } catch (e) {
            roomsList.innerHTML = '<div class="empty-state">Ошибка загрузки</div>';
        }
    }

    async function createRoom() {
        const name = roomName.value.trim();
        const capacity = parseInt(roomCapacity.value);
        const equipment = roomEquipment.value.split(',').map(s => s.trim()).filter(Boolean);
        if (!name || !capacity) {
            showMessage(adminMessage, 'Заполните название и вместимость', 'error');
            return;
        }

        try {
            const response = await apiRequest('/rooms', 'POST', { name, capacity, equipment }, true);
            if (!response.ok) {
                const data = await response.json();
                showMessage(adminMessage, data.detail || 'Ошибка', 'error');
                return;
            }
            showMessage(adminMessage, '✅ Комната создана!', 'success');
            roomName.value = '';
            roomCapacity.value = '';
            roomEquipment.value = '';
            await loadRooms(searchInput.value);
            await loadBookingRooms();
            await loadScheduleRooms();
            await loadStats();
        } catch (e) {
            showMessage(adminMessage, 'Ошибка', 'error');
        }
    }

    async function deleteRoom(roomId) {
        if (!confirm('Удалить комнату? Все бронирования в ней тоже будут удалены!')) return;
        try {
            const response = await apiRequest(`/rooms/${roomId}`, 'DELETE', null, true);
            if (!response.ok) {
                const data = await response.json();
                alert(data.detail || 'Ошибка удаления');
                return;
            }
            await loadRooms(searchInput.value);
            await loadBookingRooms();
            await loadScheduleRooms();
            await loadSchedule();
            await loadStats();
        } catch (e) {
            alert('Ошибка соединения');
        }
    }

    // --- Редактирование комнаты ---
    function openEditModal(roomId) {
        const room = allRooms.find(r => r.id === roomId);
        if (!room) return;
        editRoomId.value = roomId;
        editName.value = room.name;
        editCapacity.value = room.capacity;
        editEquipment.value = room.equipment.join(', ');
        editModal.classList.add('active');
        editMessage.classList.add('hidden');
    }

    function closeEditModal() {
        editModal.classList.remove('active');
    }

    async function saveEditRoom() {
        const roomId = parseInt(editRoomId.value);
        const name = editName.value.trim();
        const capacity = parseInt(editCapacity.value);
        const equipment = editEquipment.value.split(',').map(s => s.trim()).filter(Boolean);
        
        if (!name || !capacity) {
            showMessage(editMessage, 'Заполните все поля', 'error');
            return;
        }

        try {
            const response = await apiRequest(`/rooms/${roomId}`, 'PUT', { name, capacity, equipment }, true);
            if (!response.ok) {
                const data = await response.json();
                showMessage(editMessage, data.detail || 'Ошибка', 'error');
                return;
            }
            showMessage(editMessage, '✅ Комната обновлена!', 'success');
            setTimeout(() => {
                closeEditModal();
                loadRooms(searchInput.value);
                loadBookingRooms();
                loadScheduleRooms();
                loadStats();
            }, 500);
        } catch (e) {
            showMessage(editMessage, 'Ошибка', 'error');
        }
    }

    // --- Статистика ---
    async function loadStats() {
        try {
            const responseRooms = await apiRequest('/rooms');
            const rooms = await responseRooms.json();
            const today = new Date().toISOString().split('T')[0];
            
            let totalBookings = 0;
            let todayBookings = 0;
            let totalCapacity = 0;
            
            for (const room of rooms) {
                totalCapacity += room.capacity;
                try {
                    const resp = await apiRequest(`/rooms/${room.id}/bookings?date=${today}`);
                    const bookings = await resp.json();
                    todayBookings += bookings.length;
                } catch(e) {}
                
                // Получаем все брони для статистики (упрощённо)
                // В реальном проекте лучше сделать отдельный эндпоинт
            }
            
            // Для total используем примерное значение (можно улучшить)
            const respAll = await apiRequest('/bookings?limit=1000');
            if (respAll.ok) {
                const allBookings = await respAll.json();
                totalBookings = allBookings.length || 0;
            }
            
            statRooms.textContent = rooms.length;
            statBookings.textContent = todayBookings;
            statAvgCapacity.textContent = rooms.length ? Math.round(totalCapacity / rooms.length) : 0;
            statTotalBookings.textContent = totalBookings;
        } catch (e) {
            // Если не удалось загрузить статистику, оставляем нули
        }
    }

    // --- Бронирования ---
    async function loadBookingRooms() {
        try {
            const response = await apiRequest('/rooms');
            if (!response.ok) return;
            const rooms = await response.json();
            bookingRoomId.innerHTML = rooms.map(r => `<option value="${r.id}">${r.name}</option>`).join('');
        } catch (e) {}
    }

    async function loadScheduleRooms() {
        try {
            const response = await apiRequest('/rooms');
            if (!response.ok) return;
            const rooms = await response.json();
            scheduleRoomId.innerHTML = rooms.map(r => `<option value="${r.id}">${r.name}</option>`).join('');
        } catch (e) {}
    }

    async function createBooking() {
        const room_id = parseInt(bookingRoomId.value);
        const start_time = bookingStart.value;
        const end_time = bookingEnd.value;
        if (!room_id || !start_time || !end_time) {
            showMessage(bookingMessage, 'Заполните все поля', 'error');
            return;
        }

        try {
            const response = await apiRequest('/bookings', 'POST', { room_id, start_time, end_time }, true);
            if (!response.ok) {
                const data = await response.json();
                showMessage(bookingMessage, data.detail || 'Ошибка', 'error');
                return;
            }
            showMessage(bookingMessage, '✅ Комната забронирована!', 'success');
            await loadSchedule();
            await loadRooms(searchInput.value);
            await loadStats();
        } catch (e) {
            showMessage(bookingMessage, 'Ошибка', 'error');
        }
    }

    async function loadSchedule() {
        const room_id = parseInt(scheduleRoomId.value);
        const date = scheduleDate.value;
        if (!room_id || !date) {
            scheduleList.innerHTML = '<div class="empty-state">Выберите комнату и дату</div>';
            return;
        }

        try {
            const response = await apiRequest(`/rooms/${room_id}/bookings?date=${date}`);
            if (!response.ok) {
                scheduleList.innerHTML = '<div class="empty-state">Ошибка загрузки</div>';
                return;
            }
            const bookings = await response.json();
            if (bookings.length === 0) {
                scheduleList.innerHTML = '<div class="empty-state">📭 На этот день нет бронирований</div>';
                return;
            }
            scheduleList.innerHTML = bookings.map(b => `
                <div class="schedule-item">
                    <span><span class="time">🕐 ${b.start_time.slice(11, 16)} - ${b.end_time.slice(11, 16)}</span> <span class="user">👤 ${b.user_name}</span></span>
                    ${b.user_name === currentUser ? `<button class="cancel-btn" onclick="cancelBooking(${b.id})"><i class="fas fa-times"></i> Отменить</button>` : ''}
                </div>
            `).join('');
        } catch (e) {
            scheduleList.innerHTML = '<div class="empty-state">Ошибка</div>';
        }
    }

    async function cancelBooking(id) {
        if (!confirm('Отменить бронирование?')) return;
        try {
            const response = await apiRequest(`/bookings/${id}`, 'DELETE', null, true);
            if (!response.ok) {
                alert('Ошибка отмены');
                return;
            }
            await loadSchedule();
            await loadRooms(searchInput.value);
            await loadStats();
        } catch (e) {
            alert('Ошибка');
        }
    }

    // --- Поиск ---
    function handleSearch() {
        const filter = searchInput.value.trim();
        loadRooms(filter);
    }

    function clearSearch() {
        searchInput.value = '';
        loadRooms('');
    }

    // --- Вспомогательные ---
    function showMessage(el, text, type) {
        el.textContent = text;
        el.className = `message ${type}`;
        el.classList.remove('hidden');
        setTimeout(() => el.classList.add('hidden'), 5000);
    }

    // --- Обработчики событий ---
    authBtn.addEventListener('click', authUser);
    switchAuth.addEventListener('click', () => {
        isLogin = !isLogin;
        authTitle.textContent = isLogin ? 'Вход' : 'Регистрация';
        authBtn.innerHTML = isLogin ? '<i class="fas fa-arrow-right"></i> Войти' : '<i class="fas fa-user-plus"></i> Зарегистрироваться';
        switchAuth.textContent = isLogin ? 'Нет аккаунта? Зарегистрироваться' : 'Уже есть аккаунт? Войти';
    });
    logoutBtn.addEventListener('click', logout);
    bookingBtn.addEventListener('click', createBooking);
    scheduleBtn.addEventListener('click', loadSchedule);
    createRoomBtn.addEventListener('click', createRoom);
    searchBtn.addEventListener('click', handleSearch);
    clearSearchBtn.addEventListener('click', clearSearch);
    searchInput.addEventListener('keypress', (e) => e.key === 'Enter' && handleSearch());

    usernameInput.addEventListener('keypress', (e) => e.key === 'Enter' && authBtn.click());
    passwordInput.addEventListener('keypress', (e) => e.key === 'Enter' && authBtn.click());

    // Закрытие модального окна по клику вне его
    editModal.addEventListener('click', (e) => {
        if (e.target === editModal) closeEditModal();
    });

    // --- Автозагрузка ---
    if (token && currentUser) {
        loadApp();
    }
</script>
</body>
</html>
    """

# --- Запуск ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)