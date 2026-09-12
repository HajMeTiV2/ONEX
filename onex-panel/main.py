
import os
import uuid
from datetime import datetime
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import get_db, init_db
from utils.configs import generate_all_configs, generate_sub_list

app = FastAPI(title="ONEX V2Ray Panel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# اتصال پوشه فایل‌های فرانت‌اند
app.mount("/public", StaticFiles(directory="public"), name="public")

class LoginModel(BaseModel):
    username: str
    password: str

class CreateUserModel(BaseModel):
    username: str
    password: str
    email: str = ""
    totalTrafficGB: float = 50.0
    expireDate: str

@app.post("/api/login")
def login(data: LoginModel):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (data.username, data.password))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است")
    
    now = datetime.now().strftime("%Y/%m/%d %H:%M")
    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user["id"]))
    conn.commit()
    conn.close()
    return {"token": user["id"], "username": user["username"]}

@app.get("/api/user/{user_id}")
def get_user_dashboard(user_id: str, response: Response):
    conn = get_db()
    user = conn.cursor().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد")
        
    servers = conn.cursor().execute("SELECT * FROM servers").fetchall()
    all_configs = []
    for s in servers:
        all_configs.extend(generate_all_configs(dict(user), dict(s)))
        
    conn.close()
    return {
        "user": {
            "username": user["username"],
            "totalTrafficGB": user["total_traffic_gb"],
            "usedTrafficGB": user["used_traffic_gb"],
            "expireDate": user["expire_date"],
            "status": user["status"],
            "lastLogin": user["last_login"]
        },
        "configs": all_configs,
        "subUrl": f"/sub/{user['id']}"
    }

@app.get("/api/traffic/{user_id}")
def get_traffic_chart(user_id: str):
    conn = get_db()
    logs = conn.cursor().execute(
        "SELECT timestamp, upload_mb, download_mb FROM traffic_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 24",
        (user_id,)
    ).fetchall()
    conn.close()
    
    logs = list(reversed(logs))
    return {
        "labels": [l["timestamp"].split("T")[1][:5] if "T" in l["timestamp"] else "00:00" for l in logs],
        "upload": [l["upload_mb"] for l in logs],
        "download": [l["download_mb"] for l in logs]
    }

@app.get("/sub/{user_id}", response_class=PlainTextResponse)
def subscription(user_id: str):
    conn = get_db()
    user = conn.cursor().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user["status"] != "active":
        raise HTTPException(status_code=403, detail="ONEX: Subscription Expired")
        
    servers = conn.cursor().execute("SELECT * FROM servers").fetchall()
    all_configs = []
    for s in servers:
        all_configs.extend(generate_all_configs(dict(user), dict(s)))
        
    conn.close()
    
    total_bytes = int(user["total_traffic_gb"] * 1073741824)
    used_bytes = int(user["used_traffic_gb"] * 1073741824)
    b64_output = generate_sub_list(all_configs)
    
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Profile-Update-Interval": "6",
        "Subscription-Userinfo": f"upload=0; download={used_bytes}; total={total_bytes}; expire=0"
    }
    return PlainTextResponse(content=b64_output, headers=headers)

@app.post("/api/admin/create-user")
def admin_create_user(data: CreateUserModel):
    conn = get_db()
    new_id = str(uuid.uuid4())
    try:
        conn.cursor().execute(
            "INSERT INTO users (id, username, password, email, total_traffic_gb, expire_date) VALUES (?, ?, ?, ?, ?, ?)",
            (new_id, data.username, data.password, data.email, data.totalTrafficGB, data.expireDate)
        )
        conn.commit()
    except Exception:
        raise HTTPException(status_code=400, detail="نام کاربری قبلاً استفاده شده است")
    finally:
        conn.close()
    return {"success": True, "id": new_id, "username": data.username}

@app.get("/api/admin/users")
def admin_list_users():
    conn = get_db()
    users = conn.cursor().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(u) for u in users]

# مسیردهی صفحات HTML
@app.get("/login")
def login_page():
    return FileResponse("public/login.html")

@app.get("/dashboard/{user_id}")
def dashboard_page(user_id: str):
    return FileResponse("public/dashboard.html")

@app.get("/admin")
def admin_page():
    return FileResponse("public/admin.html")

@app.get("/")
def root():
    return FileResponse("public/login.html")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 3000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
