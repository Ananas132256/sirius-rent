# Сириус.Аренда — сервис бронирования

## Запуск
1. Установи Python 3.11+
2. В папке проекта выполни:
python -m venv venv
venv\Scripts\activate
pip install fastapi uvicorn sqlalchemy pydantic
python main.py
3. Открой в браузере: http://127.0.0.1:8000/docs

## API
- POST /rooms — создать комнату
- GET /rooms — список комнат
- GET /rooms/{id} — детали комнаты
- PUT /rooms/{id} — обновить комнату
- DELETE /rooms/{id} — удалить комнату
- POST /bookings — создать бронирование
- DELETE /bookings/{id} — отменить бронирование
- GET /rooms/{id}/bookings?date=YYYY-MM-DD — расписание

## Обработка ошибок
- 404 — не найдено
- 409 — комната уже занята

## 🔑 Данные для входа
 - **Администратор:** `admin` / `admin123`
