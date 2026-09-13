
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid
import pytz

db = SQLAlchemy()
tehran_tz = pytz.timezone('Asia/Tehran')


def now_tehran():
    return datetime.now(tehran_tz)


class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=now_tehran)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    uuid_str = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    sub_token = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))

    # Traffic (bytes)
    data_limit = db.Column(db.BigInteger, default=0)  # 0 = unlimited
    data_used = db.Column(db.BigInteger, default=0)
    upload = db.Column(db.BigInteger, default=0)
    download = db.Column(db.BigInteger, default=0)

    # Time
    expire_date = db.Column(db.DateTime, nullable=True)
    duration_days = db.Column(db.Integer, default=30)

    # Connection
    max_connections = db.Column(db.Integer, default=1)
    current_connections = db.Column(db.Integer, default=0)

    # Protocol
    protocol = db.Column(db.String(20), default='vless')

    # Status
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_tehran)
    note = db.Column(db.Text, default='')

    @property
    def is_expired(self):
        if self.expire_date is None:
            return False
        now = datetime.now(tehran_tz)
        expire = self.expire_date
        if expire.tzinfo is None:
            expire = tehran_tz.localize(expire)
        return now > expire

    @property
    def is_data_exceeded(self):
        if self.data_limit == 0:
            return False
        return self.data_used >= self.data_limit

    @property
    def status(self):
        if not self.is_active:
            return 'غیرفعال'
        if self.is_expired:
            return 'منقضی'
        if self.is_data_exceeded:
            return 'اتمام حجم'
        return 'فعال'

    @property
    def status_color(self):
        colors = {
            'فعال': 'success',
            'منقضی': 'warning',
            'اتمام حجم': 'danger',
            'غیرفعال': 'secondary'
        }
        return colors.get(self.status, 'secondary')

    @property
    def status_icon(self):
        icons = {
            'فعال': 'check-circle',
            'منقضی': 'clock',
            'اتمام حجم': 'exclamation-triangle',
            'غیرفعال': 'times-circle'
        }
        return icons.get(self.status, 'question-circle')

    @property
    def remaining_data_gb(self):
        if self.data_limit == 0:
            return '♾️'
        remaining = max(0, self.data_limit - self.data_used)
        return f"{remaining / (1024 ** 3):.2f}"

    @property
    def data_limit_gb(self):
        if self.data_limit == 0:
            return '♾️'
        return f"{self.data_limit / (1024 ** 3):.2f}"

    @property
    def data_used_gb(self):
        return f"{self.data_used / (1024 ** 3):.2f}"

    @property
    def upload_gb(self):
        return f"{self.upload / (1024 ** 3):.2f}"

    @property
    def download_gb(self):
        return f"{self.download / (1024 ** 3):.2f}"

    @property
    def remaining_days(self):
        if self.expire_date is None:
            return '♾️'
        now = datetime.now(tehran_tz)
        expire = self.expire_date
        if expire.tzinfo is None:
            expire = tehran_tz.localize(expire)
        delta = expire - now
        if delta.days < 0:
            return 0
        return delta.days

    @property
    def data_usage_percent(self):
        if self.data_limit == 0:
            return 0
        return min(100, int((self.data_used / self.data_limit) * 100))

    @property
    def time_usage_percent(self):
        if self.expire_date is None or self.duration_days == 0:
            return 0
        now = datetime.now(tehran_tz)
        expire = self.expire_date
        if expire.tzinfo is None:
            expire = tehran_tz.localize(expire)
        start = expire - timedelta(days=self.duration_days)
        total = (expire - start).total_seconds()
        elapsed = (now - start).total_seconds()
        return min(100, max(0, int((elapsed / total) * 100)))

    @property
    def expire_date_jalali(self):
        if self.expire_date is None:
            return 'نامحدود'
        return self.expire_date.strftime('%Y/%m/%d - %H:%M')

    @property
    def created_at_formatted(self):
        return self.created_at.strftime('%Y/%m/%d') if self.created_at else '-'
