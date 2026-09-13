
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, Response, jsonify, abort)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from models import db, Admin, User, tehran_tz
from utils import generate_config, generate_subscription_content, format_bytes
from config import Config
import uuid
import base64
import os

# ─── App Setup ───────────────────────────────────────
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


def init_db():
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            admin = Admin(
                username=Config.ADMIN_USERNAME,
                password_hash=generate_password_hash(Config.ADMIN_PASSWORD)
            )
            db.session.add(admin)
            db.session.commit()
            print(f"[ONEX] Admin created: {Config.ADMIN_USERNAME}")


# ─── Context Processor ──────────────────────────────
@app.context_processor
def inject_branding():
    return {
        'panel_name': Config.PANEL_NAME,
        'creator': Config.CREATOR,
        'telegram_channel': Config.TELEGRAM_CHANNEL,
        'telegram_channel_url': Config.TELEGRAM_CHANNEL_URL,
        'creator_url': Config.CREATOR_URL
    }


# ─── AUTH ────────────────────────────────────────────
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
            flash('خوش آمدید به ONEX! 🚀', 'success')
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
    total_upload = sum(u.upload for u in all_users)
    total_download = sum(u.download for u in all_users)
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # Expiring soon (next 3 days)
    now = datetime.now(tehran_tz)
    expiring_soon = [u for u in all_users
                     if u.expire_date and u.status == 'فعال'
                     and 0 <= (u.expire_date.replace(tzinfo=tehran_tz)
                               if u.expire_date.tzinfo is None
                               else u.expire_date
                               - now).days <= 3
                     ] if all_users else []

    return render_template('dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           expired_users=expired_users,
                           data_exceeded=data_exceeded,
                           disabled_users=disabled_users,
                           total_traffic=format_bytes(total_traffic),
                           total_upload=format_bytes(total_upload),
                           total_download=format_bytes(total_download),
                           recent_users=recent_users,
                           expiring_soon=len(expiring_soon))


# ─── USERS ───────────────────────────────────────────
@app.route('/users')
@login_required
def users():
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'all')
    protocol_filter = request.args.get('protocol', 'all')
    sort_by = request.args.get('sort', 'newest')

    all_users = User.query.all()

    if search:
        all_users = [u for u in all_users
                     if search.lower() in u.username.lower()
                     or search.lower() in u.note.lower()]

    if status_filter != 'all':
        all_users = [u for u in all_users if u.status == status_filter]

    if protocol_filter != 'all':
        all_users = [u for u in all_users if u.protocol == protocol_filter]

    if sort_by == 'newest':
        all_users.sort(key=lambda u: u.created_at or datetime.min, reverse=True)
    elif sort_by == 'oldest':
        all_users.sort(key=lambda u: u.created_at or datetime.min)
    elif sort_by == 'name':
        all_users.sort(key=lambda u: u.username.lower())
    elif sort_by == 'traffic':
        all_users.sort(key=lambda u: u.data_used, reverse=True)
    elif sort_by == 'expire':
        all_users.sort(key=lambda u: u.expire_date or datetime.max)

    return render_template('users.html',
                           users=all_users,
                           search=search,
                           status_filter=status_filter,
                           protocol_filter=protocol_filter,
                           sort_by=sort_by)


@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        data_limit_gb = float(request.form.get('data_limit', 0))
        duration_days = int(request.form.get('duration_days', 30))
        max_connections = int(request.form.get('max_connections', 1))
        protocol = request.form.get('protocol', 'vless')
        note = request.form.get('note', '').strip()
        count = int(request.form.get('count', 1))

        if not username:
            flash('نام کاربری الزامی است', 'danger')
            return redirect(url_for('add_user'))

        expire_date = (datetime.now(tehran_tz) + timedelta(days=duration_days)
                       if duration_days > 0 else None)
        data_limit = int(data_limit_gb * (1024 ** 3)) if data_limit_gb > 0 else 0

        created = 0
        for i in range(count):
            uname = username if count == 1 else f"{username}_{i + 1}"

            if User.query.filter_by(username=uname).first():
                flash(f'نام {uname} تکراری است', 'warning')
                continue

            user = User(
                username=uname,
                uuid_str=str(uuid.uuid4()),
                sub_token=str(uuid.uuid4()),
                data_limit=data_limit,
                expire_date=expire_date,
                duration_days=duration_days,
                max_connections=max_connections,
                protocol=protocol,
                note=note,
                is_active=True
            )
            db.session.add(user)
            created += 1

        db.session.commit()
        flash(f'✅ {created} کاربر با موفقیت ایجاد شد', 'success')
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
        user.max_connections = int(request.form.get('max_connections', 1))
        user.protocol = request.form.get('protocol', 'vless')
        user.note = request.form.get('note', '').strip()
        user.is_active = 'is_active' in request.form

        if request.form.get('reset_expire') == 'on':
            user.expire_date = (datetime.now(tehran_tz) + timedelta(days=duration_days)
                                if duration_days > 0 else None)

        if request.form.get('new_uuid') == 'on':
            user.uuid_str = str(uuid.uuid4())

        db.session.commit()
        flash(f'✅ کاربر {user.username} ویرایش شد', 'success')
        return redirect(url_for('users'))

    config_link = generate_config(user)
    sub_link = f"{request.host_url}sub/{user.sub_token}"
    sub_info_link = f"{request.host_url}sub/info/{user.sub_token}"

    return render_template('edit_user.html',
                           user=user,
                           config_link=config_link,
                           sub_link=sub_link,
                           sub_info_link=sub_info_link)


@app.route('/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    name = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'🗑️ کاربر {name} حذف شد', 'success')
    return redirect(url_for('users'))


@app.route('/users/toggle/<int:user_id>')
@login_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    s = 'فعال ✅' if user.is_active else 'غیرفعال ❌'
    flash(f'کاربر {user.username} {s} شد', 'info')
    return redirect(url_for('users'))


@app.route('/users/reset-traffic/<int:user_id>')
@login_required
def reset_traffic(user_id):
    user = User.query.get_or_404(user_id)
    user.data_used = 0
    user.upload = 0
    user.download = 0
    db.session.commit()
    flash(f'🔄 ترافیک {user.username} ریست شد', 'success')
    return redirect(url_for('edit_user', user_id=user_id))


@app.route('/users/renew/<int:user_id>')
@login_required
def renew_user(user_id):
    user = User.query.get_or_404(user_id)
    user.expire_date = datetime.now(tehran_tz) + timedelta(days=user.duration_days)
    user.data_used = 0
    user.upload = 0
    user.download = 0
    user.is_active = True
    db.session.commit()
    flash(f'🔄 اشتراک {user.username} تمدید شد', 'success')
    return redirect(url_for('users'))


# ─── BULK ACTIONS ────────────────────────────────────
@app.route('/users/bulk', methods=['POST'])
@login_required
def bulk_action():
    action = request.form.get('action')
    user_ids = request.form.getlist('user_ids')

    if not user_ids:
        flash('هیچ کاربری انتخاب نشده', 'warning')
        return redirect(url_for('users'))

    target_users = User.query.filter(User.id.in_(user_ids)).all()
    count = len(target_users)

    actions = {
        'delete': lambda u: db.session.delete(u),
        'enable': lambda u: setattr(u, 'is_active', True),
        'disable': lambda u: setattr(u, 'is_active', False),
        'reset': lambda u: [setattr(u, 'data_used', 0),
                            setattr(u, 'upload', 0),
                            setattr(u, 'download', 0)],
        'renew': lambda u: [
            setattr(u, 'expire_date',
                    datetime.now(tehran_tz) + timedelta(days=u.duration_days)),
            setattr(u, 'data_used', 0),
            setattr(u, 'is_active', True)
        ]
    }

    messages = {
        'delete': f'🗑️ {count} کاربر حذف شد',
        'enable': f'✅ {count} کاربر فعال شد',
        'disable': f'❌ {count} کاربر غیرفعال شد',
        'reset': f'🔄 ترافیک {count} کاربر ریست شد',
        'renew': f'🔄 {count} کاربر تمدید شد'
    }

    if action in actions:
        for u in target_users:
            actions[action](u)
        db.session.commit()
        flash(messages[action], 'success')

    return redirect(url_for('users'))


# ─── SUBSCRIPTION ────────────────────────────────────
@app.route('/sub/<token>')
def subscription(token):
    user = User.query.filter_by(sub_token=token).first_or_404()

    if user.status != 'فعال':
        return Response(
            base64.b64encode(b'# ONEX - Account Expired or Disabled').decode(),
            content_type='text/plain; charset=utf-8'
        )

    content = generate_subscription_content(user)

    response = Response(content, content_type='text/plain; charset=utf-8')
    response.headers['Subscription-Userinfo'] = (
        f"upload={user.upload}; "
        f"download={user.download}; "
        f"total={user.data_limit}; "
        f"expire={int(user.expire_date.timestamp()) if user.expire_date else 0}"
    )
    response.headers['Profile-Title'] = f"ONEX | {user.username}"
    response.headers['Profile-Update-Interval'] = '1'
    response.headers['Support-URL'] = Config.TELEGRAM_CHANNEL_URL
    return response


@app.route('/sub/info/<token>')
def sub_info(token):
    user = User.query.filter_by(sub_token=token).first_or_404()
    config_link = generate_config(user)
    sub_link = f"{request.host_url}sub/{user.sub_token}"

    return render_template('sub.html',
                           user=user,
                           config_link=config_link,
                           sub_link=sub_link)


# ─── SETTINGS ────────────────────────────────────────
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
            elif len(new_pass) < 6:
                flash('رمز عبور باید حداقل ۶ کاراکتر باشد', 'danger')
            else:
                current_user.password_hash = generate_password_hash(new_pass)
                db.session.commit()
                flash('✅ رمز عبور تغییر کرد', 'success')

        elif action == 'change_username':
            new_username = request.form.get('new_username', '').strip()
            if len(new_username) < 3:
                flash('نام کاربری باید حداقل ۳ کاراکتر باشد', 'danger')
            else:
                current_user.username = new_username
                db.session.commit()
                flash('✅ نام کاربری تغییر کرد', 'success')

    return render_template('settings.html', config=Config)


# ─── API ─────────────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    users = User.query.all()
    return jsonify({
        'total': len(users),
        'active': sum(1 for u in users if u.status == 'فعال'),
        'expired': sum(1 for u in users if u.status == 'منقضی'),
        'exceeded': sum(1 for u in users if u.status == 'اتمام حجم'),
        'disabled': sum(1 for u in users if u.status == 'غیرفعال'),
        'traffic': format_bytes(sum(u.data_used for u in users))
    })


@app.route('/api/user/<int:user_id>/links')
@login_required
def api_user_links(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'config': generate_config(user),
        'sub': f"{request.host_url}sub/{user.sub_token}",
        'info': f"{request.host_url}sub/info/{user.sub_token}"
    })


# ─── ERROR HANDLERS ─────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('login.html'), 404


@app.errorhandler(500)
def server_error(e):
    return '<h1>Server Error</h1>', 500


# ─── RUN ─────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
