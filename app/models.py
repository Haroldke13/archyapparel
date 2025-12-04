from . import db
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), default="/static/img/default.jpg", nullable=False)  # store relative URL


    def __repr__(self):
        return f"<Product {self.name}>"


class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _phone = db.Column('phone', db.String(20), nullable=False)

    @property
    def phone(self):
        return self._phone

    @phone.setter
    def phone(self, value):
        if value is None:
            self._phone = None
            return
        val = str(value).strip()
        if val.startswith('+254'):
            self._phone = val
        elif val.startswith('254'):
            self._phone = '+' + val
        elif val.startswith('0'):
            self._phone = '+254' + val[1:]
        else:
            self._phone = '+254' + val

    code = db.Column(db.String(10), nullable=False)
    expiry = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.utcnow() + timedelta(minutes=5)
    )

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=1)


class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=False)


class PendingPayment(db.Model):
    """Records a pending STK push initiated for a user.
    Finalization happens when the MPESA callback confirms payment.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    checkout_request_id = db.Column(db.String(128), unique=True, nullable=True)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(32), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Order(db.Model):
    """Represents a finalized order (successful payment) or a rejected/failed order for auditing."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(32), default='pending')  # 'pending', 'paid', 'rejected'
    mpesa_receipt = db.Column(db.String(128), nullable=True)
    receipt_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=True)
    product_name = db.Column(db.String(200), nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)


