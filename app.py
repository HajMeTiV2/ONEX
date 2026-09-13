import os
import json
import base64
import uuid
import time
import subprocess
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, Response, jsonify)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from models import db, Admin, User, tehran_tz
from utils import generate_config, generate_subscription_content, format_bytes

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'ابتدا وارد شوید'


@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))


@app.context_processor
def inject_branding():
    return {
        'panel_name': Config.PANEL_NAME,
        'creator': Config.CREATOR,
        'telegram_channel': Config.TELEGRAM_CHANNEL,
        'telegram_channel_url': Config.TELEGRAM_CHANNEL_URL,
        'creator_url': Config.CREATOR_URL
    }


def sync_xray_config():
    """همگام‌سازی کاربران فعال و راه‌اندازی مجدد هسته Xray"""
    with app.app_context():
        try:
            active_users = User.query.filter_by(is_active=True).all()
            clients = []
            for u in active_users:
                if u.status == 'فعال':
                    clients.append({
                        "id": u.uuid_str,
                        "email": u.username
                    })

            xray_config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "port": 10000,
                    "listen": "127.0.0.1",
                    "protocol": "vless",
                    "settings": {
                        "clients": clients,
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "ws",
                        "wsSettings": {
                            "path": "/ws"
                        }
                    }
                }],
                "outbounds": [{
                    "protocol": "freedom"
                }]
            }

            # نوشتن تنظیمات جدید
            with open('/app/xray_config.json', 'w') as f:
                json.dump(xray_config, f, indent=2)

            # کشتن پردازش قبلی Xray
            subprocess.run(["pkill", "-9", "-f", "xray"], stderr=subprocess.DEVNULL)
            time.sleep(0.5)

            # اجرای مجدد و زنده نگه داشتن هسته Xray
            subprocess.Popen(["xray", "-config", "/app/xray_config.json"])
            print("[ONEX] Xray Core successfully synced & restarted!")
        except Exception as e:
            print(f"[ONEX] Xray Sync Error: {e}")


# ─── AUTH ROUTES ─────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin, remember=True)
            flash('خوش آمدید! 🚀', 'success')
            return redirect(url_for('dashboard'))
        flash('نام کاربری یا رمز عبور اشتباه است', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─── DASHBOARD ───────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    all_users = User.query.all()
    total_users = len(all_users)
    active_users = sum(1 for u in all_users if u.status == 'فعال')
    expired_users = sum(1 for u in all_users if u.status == 'منقضی')
    data_exceeded = sum(1 for u in all_users if u.status == 'اتمام حجم')
    disabled_users = sum(1 for u in all_users if u.status == 'غیرفعال')
    total_traffic = sum(u.data_used for u in all_users)
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    return render_template('dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           expired_users=expired_users,
                           data_exceeded=data_exceeded,
                           disabled_users=disabled_users,
                           total_traffic=format_bytes(total_traffic),
                           recent_users=recent_users)


# ─── USER MANAGEMENT ─────────────────────────────────
@app.route('/users')
@login_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=all_users)


@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        data_limit_gb = float(request.form.get('data_limit', 0))
        duration_days = int(request.form.get('duration_days', 30))
        protocol = request.form.get('protocol', 'vless')

        if User.query.filter_by(username=username).first():
            flash('این نام کاربری وجود دارد', 'danger')
            return redirect(url_for('add_user'))

        expire_date = datetime.now(tehran_tz) + timedelta(days=duration_days) if duration_days > 0 else None
        data_limit = int(data_limit_gb * (1024 ** 3)) if data_limit_gb > 0 else 0

        user = User(
            username=username,
            uuid_str=str(uuid.uuid4()),
            sub_token=str(uuid.uuid4()),
            data_limit=data_limit,
            expire_date=expire_date,
            duration_days=duration_days,
            protocol=protocol,
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

        sync_xray_config()
        flash(f'✅ کاربر {username} با موفقیت ساخته شد', 'success')
        return redirect(url_for('users'))

    return render_template('add_user.html')


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        data_limit_gb = float(request.form.get('data_limit', 0))
        user.data_limit = int(data_limit_gb * (1024 ** 3)) if data_limit_gb > 0 else 0

        duration_days = int(request.form.get('duration_days', 30))
        user.duration_days = duration_days
        user.protocol = request.form.get('protocol', 'vless')
        user.is_active = 'is_active' in request.form

        db.session.commit()
        sync_xray_config()
        flash(f'✅ کاربر {user.username} ویرایش شد', 'success')
        return redirect(url_for('users'))

    domain = request.host.split(':')[0]
    config_link = generate_config(user, domain)
    sub_link = f"{request.host_url}sub/{user.sub_token}"

    return render_template('edit_user.html',
                           user=user,
                           config_link=config_link,
                           sub_link=sub_link,
                           sub_info_link=sub_link)


@app.route('/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    sync_xray_config()
    flash('کاربر حذف شد', 'success')
    return redirect(url_for('users'))


@app.route('/users/toggle/<int:user_id>')
@login_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    sync_xray_config()
    flash(f'وضعیت کاربر تغییر کرد', 'info')
    return redirect(url_for('users'))


@app.route('/users/renew/<int:user_id>')
@login_required
def renew_user(user_id):
    user = User.query.get_or_404(user_id)
    user.expire_date = datetime.now(tehran_tz) + timedelta(days=user.duration_days)
    user.data_used = 0
    user.is_active = True
    db.session.commit()
    sync_xray_config()
    flash(f'اشتراک کاربر تمدید شد', 'success')
    return redirect(url_for('users'))


# ─── SUBSCRIPTION ROUTES ─────────────────────────────
@app.route('/sub/<token>')
def subscription(token):
    user = User.query.filter_by(sub_token=token).first_or_404()
    domain = request.host.split(':')[0]

    user_agent = request.headers.get('User-Agent', '').lower()
    accept_header = request.headers.get('Accept', '').lower()

    v2ray_clients = [
        'v2ray', 'v2rayng', 'shadowrocket', 'streisand', 'clash',
        'sing-box', 'neko', 'quantumult', 'stash', 'surfboard',
        'foxray', 'passwall', 'hiddify', 'subconverter', 'go-http-client'
    ]

    is_v2ray_client = any(client in user_agent for client in v2ray_clients)
    is_browser = 'text/html' in accept_header or ('mozilla' in user_agent and not is_v2ray_client)

    if is_browser and not is_v2ray_client:
        config_link = generate_config(user, domain)
        sub_link = f"{request.url_root}sub/{user.sub_token}"
        return render_template('sub.html', user=user, config_link=config_link, sub_link=sub_link)

    if user.status != 'فعال':
        return Response(
            base64.b64encode(b'# ONEX - Account Expired or Disabled').decode(),
            content_type='text/plain; charset=utf-8'
        )

    content = generate_subscription_content(user, domain)
    response = Response(content, content_type='text/plain; charset=utf-8')
    response.headers['Subscription-Userinfo'] = (
        f"upload={user.upload}; "
        f"download={user.download}; "
        f"total={user.data_limit}; "
        f"expire={int(user.expire_date.timestamp()) if user.expire_date else 0}"
    )
    response.headers['Profile-Title'] = f"ONEX | {user.username}"
    return response


@app.route('/sub/info/<token>')
def sub_info(token):
    return redirect(url_for('subscription', token=token))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            old_pass = request.form.get('old_password')
            new_pass = request.form.get('new_password')
            confirm_pass = request.form.get('confirm_password')

            if not check_password_hash(current_user.password_hash, old_pass):
                flash('رمز عبور فعلی اشتباه است', 'danger')
            elif new_pass != confirm_pass:
                flash('رمز عبور جدید مطابقت ندارد', 'danger')
            else:
                current_user.password_hash = generate_password_hash(new_pass)
                db.session.commit()
                flash('✅ رمز عبور تغییر کرد', 'success')

    return render_template('settings.html', config=Config)


def init_db():
    with app.app_context():
        try:
            db.create_all()
            if not Admin.query.first():
                admin = Admin(
                    username=Config.ADMIN_USERNAME,
                    password_hash=generate_password_hash(Config.ADMIN_PASSWORD)
                )
                db.session.add(admin)
                db.session.commit()
        except Exception as e:
            print(f"[ONEX] DB Init Error: {e}")


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
