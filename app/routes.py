from .models import Product
from . import db
from datetime import datetime
import random
from .models import VerificationCode
import os
from flask import Blueprint, abort, render_template, request, redirect, url_for, flash, jsonify, current_app
from functools import wraps
from sqlalchemy.exc import IntegrityError
import os
from werkzeug.utils import secure_filename
from .models import User, Product, PendingPayment, Order, OrderItem
from .forms import ContactForm
from .forms import SignupForm, ProductForm
from flask import redirect, url_for, flash
from flask_login import current_user, login_required
from .models import Cart, Wishlist, Product
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, current_user, logout_user, login_required
from .models import User
from .forms import LoginForm



main = Blueprint("main", __name__)


def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return abort(403)
        return f(*args, **kwargs)
    return wrap



@main.route("/admin/products")
@admin_required
def admin_products():
    products = Product.query.all()
    return render_template("admin_products.html", products=products)


@main.route('/admin/orders')
@admin_required
def admin_orders():
    # simple pagination & filtering
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    status_filter = request.args.get('status')  # optional: 'paid', 'rejected', etc.

    q = Order.query
    if status_filter:
        q = q.filter_by(status=status_filter)
    orders_pagination = q.order_by(Order.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    orders = orders_pagination.items

    pq = PendingPayment.query
    pendings = pq.order_by(PendingPayment.created_at.desc()).limit(200).all()

    # eager load users for display
    user_ids = set([o.user_id for o in orders] + [p.user_id for p in pendings if p.user_id])
    user_map = {u.id: u for u in User.query.filter(User.id.in_(list(user_ids))).all()} if user_ids else {}

    # helper: list mpesa audit JSON files for linking (recent)
    audit_folder = os.path.join(current_app.root_path, 'static', 'mpesa_logs')
    audit_files = []
    if os.path.isdir(audit_folder):
        for fn in sorted(os.listdir(audit_folder), reverse=True)[:50]:
            if fn.endswith('.json'):
                audit_files.append(fn)

    return render_template('admin_orders.html', orders=orders, pendings=pendings, user_map=user_map, orders_pagination=orders_pagination, audit_files=audit_files)


@main.route('/admin/order/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    items = OrderItem.query.filter_by(order_id=order.id).all()
    user = User.query.get(order.user_id)
    return render_template('admin_order_detail.html', order=order, items=items, user=user)



@main.route("/")
def home():
    # Fetch new arrivals from DB
    new_arrivals = Product.query.limit(8).all()
    return render_template("home.html", new_arrivals=new_arrivals)


@main.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.id)
    return render_template('profile.html', user=user)



@main.route("/shop")
def shop():
    search_query = request.args.get('q', '').strip()

    if search_query:
        products = Product.query.filter(Product.name.ilike(f"%{search_query}%")).all()
    else:
        products = Product.query.all()

    return render_template("shop.html", products=products)


from flask import jsonify
from flask_login import current_user, login_required

@main.route("/add_to_cart/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id):
    existing = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()

    if existing:
        existing.quantity += 1
    else:
        new_item = Cart(user_id=current_user.id, product_id=product_id, quantity=1)
        db.session.add(new_item)

    db.session.commit()

    # If request expects JSON (AJAX), return updated counts
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        cart_count = Cart.query.filter_by(user_id=current_user.id).count()
        return jsonify({"message": "Added to cart", "cart_count": cart_count})

    return jsonify({"message": "Added to cart"})


@main.route("/add_to_wishlist/<int:product_id>", methods=["POST"])
@login_required
def add_to_wishlist(product_id):
    existing = Wishlist.query.filter_by(user_id=current_user.id, product_id=product_id).first()

    if existing:
        return jsonify({"message": "Already in wishlist"})

    new_item = Wishlist(user_id=current_user.id, product_id=product_id)
    db.session.add(new_item)
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        wishlist_count = Wishlist.query.filter_by(user_id=current_user.id).count()
        return jsonify({"message": "Added to wishlist", "wishlist_count": wishlist_count})

    return jsonify({"message": "Added to wishlist"})




def get_cart_total(user_id):
    items = Cart.query.filter_by(user_id=user_id).all()
    total = 0
    for item in items:
        product = Product.query.get(item.product_id)
        if product:
            total += product.price * item.quantity
    return total


import requests
import base64
from datetime import datetime
from flask import current_app
import logging
import json
import re


def canonicalize_phone(raw):
    """Return canonical phone format used in DB: 2547XXXXXXXX (no leading +)."""
    if not raw:
        return None
    s = str(raw).strip()
    # remove spaces and common separators
    s = re.sub(r"[\s\-()]+", '', s)
    # remove leading plus
    if s.startswith('+'):
        s = s[1:]
    # If starts with 0 -> replace with 254
    if s.startswith('0') and len(s) >= 9:
        s = '254' + s[1:]
    # if starts with 7xxxxxxxx (no leading 0) -> add 254
    if re.match(r'^7\d{8}$', s):
        s = '254' + s
    # if already starts with 254 keep as-is
    s = s.lstrip('+')
    return s

def get_access_token():
    consumer_key = current_app.config.get("MPESA_CONSUMER_KEY")
    consumer_secret = current_app.config.get("MPESA_CONSUMER_SECRET")

    if not consumer_key or not consumer_secret:
        current_app.logger.error("MPESA consumer key/secret missing in config")
        raise RuntimeError("MPESA credentials not configured")

    try:
        auth = requests.get(
            "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
            auth=(consumer_key, consumer_secret),
            timeout=10
        )
        auth.raise_for_status()
    except requests.RequestException:
        # Log full response/text where possible for debugging
        current_app.logger.exception("Failed to fetch MPESA access token")
        raise

    # Safely parse JSON and ensure token exists
    try:
        data = auth.json()
    except ValueError:
        current_app.logger.error("MPESA auth returned non-JSON response: %s", auth.text)
        raise RuntimeError("Invalid response from MPESA auth endpoint")

    token = data.get('access_token')
    if not token:
        current_app.logger.error("MPESA auth response missing access_token: %s", data)
        raise RuntimeError("MPESA auth did not return access token")

    return token


def send_stk_push(phone, amount):
    try:
        token = get_access_token()
    except Exception as e:
        current_app.logger.exception("Unable to obtain MPESA access token")
        raise

    shortcode = current_app.config.get("MPESA_SHORTCODE")
    passkey = current_app.config.get("MPESA_PASSKEY")
    callback = current_app.config.get("MPESA_CALLBACK_URL")

    if not shortcode or not passkey or not callback:
        current_app.logger.error("MPESA configuration incomplete (shortcode/passkey/callback)")
        raise RuntimeError("MPESA configuration incomplete")

    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((shortcode + passkey + timestamp).encode()).decode()

    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": shortcode,
        "PhoneNumber": phone,
        "CallBackURL": callback,
        "AccountReference": "Mitumba Store",
        "TransactionDesc": "Order Payment"
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers=headers,
            timeout=10
        )
        resp.raise_for_status()
    except requests.RequestException:
        current_app.logger.exception("MPESA STK push request failed")
        # include resp.text when available for debugging
        try:
            body_text = resp.text
        except Exception:
            body_text = '<no response body>'
        raise RuntimeError(f"MPESA STK push failed: {body_text}")

    # try to parse JSON; if not JSON, return text for debugging
    try:
        return resp.json()
    except ValueError:
        current_app.logger.error("MPESA STK push returned non-JSON: %s", resp.text)
        return {"raw_response": resp.text}


@main.route("/process_checkout", methods=["POST"])
@login_required
def process_checkout():
    # Process checkout via M-Pesa STK push using MPESA credentials from config/.env
    phone = request.form.get("phone")
    amount = get_cart_total(current_user.id)

    # normalize phone to party format
    if not phone:
        flash("Phone number is required", "danger")
        return render_template("checkout.html", success=False, mpesa_response=None, phone=phone, total=amount)

    p = str(phone).strip()
    if p.startswith('0'):
        party_phone = '+254' + p[1:]
    elif p.startswith('+'):
        party_phone = p
    elif p.startswith('254'):
        party_phone = '+' + p
    else:
        party_phone = '+254' + p

    # Obtain access token
    token = get_mpesa_access_token()
    if not token:
        current_app.logger.error('Could not obtain MPESA access token')
        flash("Payment provider error: unable to initiate M-Pesa request. Please try again later.", "danger")
        return render_template("checkout.html", success=False, mpesa_response=None, phone=phone, total=amount)

    shortcode = current_app.config.get('MPESA_SHORTCODE') or os.getenv('MPESA_SHORTCODE')
    passkey = current_app.config.get('MPESA_PASSKEY') or os.getenv('MPESA_PASSKEY')
    callback = current_app.config.get('MPESA_CALLBACK_URL') or os.getenv('MPESA_CALLBACK_URL')

    if not shortcode or not passkey or not callback:
        current_app.logger.error('MPESA configuration incomplete')
        flash("Payment provider configuration missing. Contact support.", "danger")
        return render_template("checkout.html", success=False, mpesa_response=None, phone=phone, total=amount)

    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()

    # MPESA API expects phone numbers without a leading '+' (e.g. 2547XXXXXXXX)
    mpesa_party = party_phone.lstrip('+')
    payload = {
        'BusinessShortCode': shortcode,
        'Password': password,
        'Timestamp': timestamp,
        'TransactionType': 'CustomerPayBillOnline',
        'Amount': int(float(amount)),
        'PartyA': mpesa_party,
        'PartyB': shortcode,
        'PhoneNumber': mpesa_party,
        'CallBackURL': callback,
        # Optional: QueueTimeOutURL helps sandbox respond when timeout occurs
        'QueueTimeOutURL': callback,
        'AccountReference': 'Mitumba Store',
        'TransactionDesc': 'Order Payment'
    }

    # audit payload
    _save_json_audit('checkout_payload', payload)

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    try:
        resp = requests.post('https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest', json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
    except requests.RequestException:
        # capture response text if available and save for debugging
        try:
            err_text = resp.text
        except Exception:
            err_text = '<no response body>'
        _save_json_audit('checkout_error', {'status': getattr(resp, 'status_code', None), 'body': err_text})
        # Log full response for debugging
        current_app.logger.error('MPESA STK push request failed (status=%s): %s', getattr(resp, 'status_code', None), err_text)
        # In development show the raw MPESA response in the flash so developer can iterate faster
        if os.getenv('FLASK_ENV') == 'development':
            flash(f"Payment provider error: {err_text}", 'danger')
        else:
            flash("Payment provider error: unable to reach M-Pesa or invalid request. Please try again later.", "danger")
        return render_template("checkout.html", success=False, mpesa_response=None, phone=phone, total=amount)

    try:
        resp_data = resp.json()
    except Exception:
        resp_data = {'raw': resp.text}

    _save_json_audit('checkout_response', resp_data)

    # handle success code
    if str(resp_data.get('ResponseCode')) == '0' or resp_data.get('ResponseCode') == 0:
        # generate billing pdf and clear cart
        raw_items = Cart.query.filter_by(user_id=current_user.id).all()
        cart_items = []
        total_calc = 0
        for it in raw_items:
            prod = Product.query.get(it.product_id)
            if not prod:
                prod = type('P', (), {'id': None, 'name': 'Unknown', 'price': 0.0, 'image_url': '/static/img/default.jpg'})
            cart_items.append(type('CI', (), {'id': it.id, 'product': prod, 'quantity': it.quantity}))
            total_calc += prod.price * it.quantity

        pdf_path = generate_billing_pdf(current_user.username, cart_items, total_calc)
        Cart.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

        flash('Payment initiated. Check your phone to complete the transaction.', 'success')
        return render_template('checkout.html', success=True, mpesa_response=resp_data, phone=phone, total=amount)

    # failure
    current_app.logger.error('STK Push failed: %s', resp_data)
    flash('Payment failed to initiate. Please try again or contact support.', 'danger')
    return render_template('checkout.html', success=False, mpesa_response=resp_data, phone=phone, total=amount)


def get_mpesa_access_token():
    """Obtain MPESA access token using credentials from config or environment.
    Returns the token string or None on failure.
    """
    consumer_key = current_app.config.get('MPESA_CONSUMER_KEY') or os.getenv('MPESA_CONSUMER_KEY')
    consumer_secret = current_app.config.get('MPESA_CONSUMER_SECRET') or os.getenv('MPESA_CONSUMER_SECRET')

    if not consumer_key or not consumer_secret:
        logging.error('MPESA consumer credentials missing')
        return None

    url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    creds = f"{consumer_key}:{consumer_secret}"
    encoded = base64.b64encode(creds.encode('utf-8')).decode('utf-8')
    headers = {'Authorization': f'Basic {encoded}'}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        token = data.get('access_token')
        if token:
            logging.info('Obtained MPESA access token')
            return token
        logging.error('MPESA token not present in response: %s', data)
        return None
    except requests.RequestException as e:
        logging.exception('Error obtaining MPESA token: %s', e)
        return None


def _save_json_audit(prefix, payload):
    """Save payload/response JSON to static/mpesa_logs with timestamped filename."""
    folder = os.path.join(current_app.root_path, 'static', 'mpesa_logs')
    os.makedirs(folder, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    fname = f"{prefix}_{ts}.json"
    path = os.path.join(folder, fname)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        logging.exception('Failed to write MPESA audit file')
    return path


@main.route('/mpesa/stk_push', methods=['POST'])
@login_required
def mpesa_stk_push():
    """Endpoint to initiate STK push. Expects JSON {phone_number, amount} and returns receipt info or error."""
    if request.content_type != 'application/json':
        return jsonify({'error': 'Content-Type must be application/json'}), 415

    data = request.get_json()
    phone = data.get('phone_number') or data.get('phone')
    amount = data.get('amount')

    # Normalize and validate phone
    if not phone:
        return jsonify({'error': 'phone_number required'}), 400
    phone = str(phone).strip()
    # Accept 07xxxxxxx, 2547xxxxxxxx, or +2547xxxxxxxx
    if not re.match(r'^(?:\+?2547\d{8}|07\d{8})$', phone):
        return jsonify({'error': 'Invalid phone number format'}), 400

    # Normalize to international format and MPESA expects no leading '+' in requests
    if phone.startswith('0'):
        party_phone = '254' + phone[1:]
    elif phone.startswith('+'):
        party_phone = phone.lstrip('+')
    elif phone.startswith('254'):
        party_phone = phone
    else:
        party_phone = '254' + phone

    try:
        amount_val = int(float(amount))
        if amount_val <= 0:
            raise ValueError()
    except Exception:
        return jsonify({'error': 'Invalid amount'}), 400

    # get token
    token = get_mpesa_access_token()
    if not token:
        return jsonify({'error': 'Failed to obtain M-Pesa access token'}), 500

    shortcode = current_app.config.get('MPESA_SHORTCODE') or os.getenv('MPESA_SHORTCODE')
    passkey = current_app.config.get('MPESA_PASSKEY') or os.getenv('MPESA_PASSKEY')
    callback = current_app.config.get('MPESA_CALLBACK_URL') or os.getenv('MPESA_CALLBACK_URL')

    if not shortcode or not passkey or not callback:
        return jsonify({'error': 'MPESA configuration incomplete'}), 500

    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()

    payload = {
        'BusinessShortCode': shortcode,
        'Password': password,
        'Timestamp': timestamp,
        'TransactionType': 'CustomerPayBillOnline',
        'Amount': amount_val,
        'PartyA': party_phone,
        'PartyB': shortcode,
        'PhoneNumber': party_phone,
        'CallBackURL': callback,
        'AccountReference': 'Mitumba Store',
        'TransactionDesc': 'Order Payment'
    }

    _save_json_audit('stk_payload', payload)

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    try:
        resp = requests.post('https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest', json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        try:
            err_text = resp.text
        except Exception:
            err_text = '<no response body>'
        _save_json_audit('stk_error', {'status': getattr(resp, 'status_code', None), 'body': err_text})
        logging.exception('STK push request failed: %s', err_text)
        return jsonify({'error': 'STK Push request failed', 'details': err_text}), 502

    try:
        resp_data = resp.json()
    except Exception:
        resp_data = {'raw': resp.text}

    _save_json_audit('stk_response', resp_data)

    # Build cart items for PDF (reuse existing generate_billing_pdf format)
    raw_items = Cart.query.filter_by(user_id=current_user.id).all()
    cart_items = []
    total = 0
    for it in raw_items:
        prod = Product.query.get(it.product_id)
        if not prod:
            prod = type('P', (), {'id': None, 'name': 'Unknown', 'price': 0.0, 'image_url': '/static/img/default.jpg'})
        cart_items.append(type('CI', (), {'id': it.id, 'product': prod, 'quantity': it.quantity}))
        total += prod.price * it.quantity

    # On success ResponseCode == '0'
    if str(resp_data.get('ResponseCode')) == '0' or resp_data.get('ResponseCode') == 0:
        # Create a pending payment record; do NOT clear the cart until callback confirms payment
        checkout_id = resp_data.get('CheckoutRequestID') or resp_data.get('CheckoutRequestID')
        pending = PendingPayment(user_id=current_user.id, checkout_request_id=checkout_id, amount=total)
        db.session.add(pending)
        db.session.commit()

        receipt_info = {
            'message': 'Payment initiated. Check your phone to complete the transaction.',
            'CheckoutRequestID': checkout_id
        }
        _save_json_audit('stk_success', {'pending': {'id': pending.id, 'checkout_request_id': checkout_id}, 'resp': resp_data})
        return jsonify(receipt_info)

    # failure
    _save_json_audit('stk_failed', resp_data)
    return jsonify({'error': 'STK Push failed', 'details': resp_data}), 500


@main.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    data = request.get_json() or {}
    _save_json_audit('callback', data)
    logging.info('M-Pesa callback received')

    try:
        body = data.get('Body', {})
        stk = body.get('stkCallback', {})
        result_code = stk.get('ResultCode')

        # Extract common callback metadata values (available in many callbacks)
        items = stk.get('CallbackMetadata', {}).get('Item', [])
        amount = next((it.get('Value') for it in items if it.get('Name') == 'Amount'), None)
        receipt = next((it.get('Value') for it in items if it.get('Name') == 'MpesaReceiptNumber'), None)
        phone = next((it.get('Value') for it in items if it.get('Name') == 'PhoneNumber'), None)

        # helper to produce phone variants for matching stored user.phone values
        def phone_variants(raw):
            raw = str(raw or '')
            variants = set()
            if not raw:
                return variants
            # strip spaces
            raw = re.sub(r'\s+', '', raw)
            # strip leading +
            if raw.startswith('+'):
                raw = raw[1:]
            variants.add(raw)

            # if starts with 2547..., add 07... and +2547...
            if raw.startswith('254') and len(raw) >= 6:
                # assume mobile starting at 2547...
                if raw[3] == '7':
                    variants.add('0' + raw[3:])
                    variants.add('+{}'.format(raw))

            # if starts with 07xxxxxxx
            if raw.startswith('07'):
                variants.add(raw[1:])            # 7xxxxxxxx
                variants.add('254' + raw[1:])    # 2547xxxxxxxx
                variants.add('+254' + raw[1:])   # +2547xxxxxxxx
                variants.add(raw)                # 07xxxxxxxx

            # if starts with 7xxxxxxxx (no leading zero)
            if re.match(r'^7\d{8}$', raw):
                variants.add('0' + raw)
                variants.add('254' + raw)
                variants.add('+254' + raw)

            # As a final attempt, add versions without any leading +
            variants = {v.lstrip('+') for v in variants}
            return variants

        if result_code == 0:

            # try find user by CheckoutRequestID first, then by phone variants
            crid = stk.get('CheckoutRequestID') or stk.get('CheckoutRequestID')
            pending = None
            user = None

            if crid:
                pending = PendingPayment.query.filter_by(checkout_request_id=crid).first()
                if pending:
                    user = User.query.get(pending.user_id)

            # helper to produce phone variants for matching stored user.phone values
            def phone_variants(raw):
                raw = str(raw or '')
                variants = set()
                if not raw:
                    return variants
                # strip spaces
                raw = re.sub(r'\s+', '', raw)
                # strip leading +
                if raw.startswith('+'):
                    raw = raw[1:]
                variants.add(raw)

                # if starts with 2547..., add 07... and +2547...
                if raw.startswith('254') and len(raw) >= 6:
                    # assume mobile starting at 2547...
                    if raw[3] == '7':
                        variants.add('0' + raw[3:])
                        variants.add('+{}'.format(raw))

                # if starts with 07xxxxxxx
                if raw.startswith('07'):
                    variants.add(raw[1:])            # 7xxxxxxxx
                    variants.add('254' + raw[1:])    # 2547xxxxxxxx
                    variants.add('+254' + raw[1:])   # +2547xxxxxxxx
                    variants.add(raw)                # 07xxxxxxxx

                # if starts with 7xxxxxxxx (no leading zero)
                if re.match(r'^7\d{8}$', raw):
                    variants.add('0' + raw)
                    variants.add('254' + raw)
                    variants.add('+254' + raw)

                # As a final attempt, add versions without any leading +
                variants = {v.lstrip('+') for v in variants}
                return variants

            if not user and phone:
                variants = phone_variants(phone)
                if variants:
                    # attempt to find a User whose phone matches any variant
                    user = User.query.filter(User.phone.in_(list(variants))).first()

            # If still no user but we have a pending (from CRID) attempt to load user
            if not user and pending:
                user = User.query.get(pending.user_id)

            if user:
                # ensure pending is set (prefer CRID match, else most recent pending for user)
                if not pending:
                    pending = PendingPayment.query.filter_by(user_id=user.id, status='pending').order_by(PendingPayment.created_at.desc()).first()
                # build cart items and total for this user
                raw_items = Cart.query.filter_by(user_id=user.id).all()
                cart_items = []
                total = 0
                for it in raw_items:
                    prod = Product.query.get(it.product_id)
                    if not prod:
                        prod = type('P', (), {'id': None, 'name': 'Unknown', 'price': 0.0, 'image_url': '/static/img/default.jpg'})
                    cart_items.append(type('CI', (), {'id': it.id, 'product': prod, 'quantity': it.quantity}))
                    total += prod.price * it.quantity

                # Create Order and OrderItems (mark as paid)
                try:
                    order = Order(user_id=user.id, total_amount=total, status='paid', mpesa_receipt=receipt)
                    db.session.add(order)
                    db.session.flush()  # get order.id

                    for it in cart_items:
                        prod = it.product
                        oi = OrderItem(
                            order_id=order.id,
                            product_id=getattr(prod, 'id', None),
                            product_name=getattr(prod, 'name', 'Unknown'),
                            unit_price=getattr(prod, 'price', 0.0),
                            quantity=it.quantity
                        )
                        db.session.add(oi)
                except Exception:
                    logging.exception('Failed to create Order records')

                # generate receipt and clear cart
                try:
                    pdf_path = generate_billing_pdf(user.username, cart_items, total)
                    # If order exists, attach receipt_path
                    try:
                        if 'order' in locals() and order:
                            order.receipt_path = pdf_path
                            db.session.add(order)
                    except Exception:
                        logging.exception('Failed to attach receipt_path to order')
                except Exception:
                    logging.exception('Failed to generate billing PDF')
                    pdf_path = None

                # Only clear cart and mark pending completed when we successfully generated receipt (or even if pdf failed, we still mark paid)
                try:
                    Cart.query.filter_by(user_id=user.id).delete()
                    if pending:
                        pending.status = 'completed'
                        db.session.add(pending)
                    db.session.commit()
                except Exception:
                    logging.exception('Failed to finalize payment and clear cart')
                    db.session.rollback()

                receipt_url = None
                if pdf_path:
                    receipt_url = url_for('static', filename=os.path.relpath(pdf_path, os.path.join(current_app.root_path, 'static')))

                return jsonify({'success': True, 'receipt_url': receipt_url}), 200

            # If we reach here, we didn't match a user; keep pending untouched and log for manual reconciliation
            logging.info('MPESA callback: no matching user for phone=%s, CheckoutRequestID=%s', phone, crid)
            return jsonify({'success': True, 'message': 'Callback processed; user not found for phone'}), 200

        else:
            # Payment failed or was cancelled. Attempt to record a rejected order for auditing and mark pending as failed.
            crid = stk.get('CheckoutRequestID') or stk.get('CheckoutRequestID')
            pending = None
            user = None
            if crid:
                pending = PendingPayment.query.filter_by(checkout_request_id=crid).first()
                if pending:
                    user = User.query.get(pending.user_id)

            # try locate user via phone variants if not found
            if not user and phone:
                variants = phone_variants(phone)
                if variants:
                    user = User.query.filter(User.phone.in_(list(variants))).first()

            if user:
                raw_items = Cart.query.filter_by(user_id=user.id).all()
                total = 0
                items_for_order = []
                for it in raw_items:
                    prod = Product.query.get(it.product_id)
                    if not prod:
                        prod = type('P', (), {'id': None, 'name': 'Unknown', 'price': 0.0, 'image_url': '/static/img/default.jpg'})
                    items_for_order.append({'product': prod, 'quantity': it.quantity})
                    total += prod.price * it.quantity

                try:
                    order = Order(user_id=user.id, total_amount=total or (pending.amount if pending else 0.0), status='rejected', mpesa_receipt=receipt or f'ResultCode:{result_code}')
                    db.session.add(order)
                    db.session.flush()
                    for it in items_for_order:
                        prod = it['product']
                        oi = OrderItem(
                            order_id=order.id,
                            product_id=getattr(prod, 'id', None),
                            product_name=getattr(prod, 'name', 'Unknown'),
                            unit_price=getattr(prod, 'price', 0.0),
                            quantity=it['quantity']
                        )
                        db.session.add(oi)

                    if pending:
                        pending.status = 'failed'
                        db.session.add(pending)

                    db.session.commit()
                except Exception:
                    logging.exception('Failed to create rejected Order records')
                    db.session.rollback()

            else:
                # No user identified; if there's a pending payment, mark it failed for manual reconciliation
                if pending:
                    try:
                        pending.status = 'failed'
                        db.session.add(pending)
                        db.session.commit()
                    except Exception:
                        logging.exception('Failed to mark pending payment as failed')
                        db.session.rollback()
                logging.info('MPESA callback: payment failed but no matching user found. CheckoutRequestID=%s', crid)

            return jsonify({'error': 'Payment failed or cancelled', 'details': stk}), 400

    except Exception as e:
        logging.exception('Callback processing error: %s', e)
        return jsonify({'error': 'Callback processing error'}), 500



"""
@main.route("/add_to_cart/<int:product_id>")
@login_required
def add_to_cart(product_id):
    existing = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()

    if existing:
        existing.quantity += 1
    else:
        new_item = Cart(user_id=current_user.id, product_id=product_id)
        db.session.add(new_item)

    db.session.commit()
    flash("Added to cart!", "success")
    return redirect(url_for('main.shop'))


@main.route("/add_to_wishlist/<int:product_id>")
@login_required
def add_to_wishlist(product_id):
    exists = Wishlist.query.filter_by(user_id=current_user.id, product_id=product_id).first()

    if exists:
        flash("Product already in wishlist.", "info")
    else:
        item = Wishlist(user_id=current_user.id, product_id=product_id)
        db.session.add(item)
        db.session.commit()
        flash("Added to wishlist!", "success")

    return redirect(url_for('main.shop'))
"""



@main.route("/product/<int:id>")
def product(id):
    item = Product.query.get_or_404(id)
    return render_template("product.html", item=item)


@main.route('/cart')
@login_required
def cart():
    raw_items = Cart.query.filter_by(user_id=current_user.id).all()
    # build items with product attribute for templates
    cart_items = []
    for it in raw_items:
        prod = Product.query.get(it.product_id)
        if not prod:
            # create a lightweight fallback product to avoid template errors
            prod = type('P', (), {'id': None, 'name': 'Unknown product', 'price': 0.0, 'image_url': '/static/img/default.jpg'})
        cart_items.append(type('CI', (), {'id': it.id, 'product': prod, 'quantity': it.quantity}))

    total = get_cart_total(current_user.id)
    phone = getattr(current_user, 'phone', '')
    return render_template('cart.html', cart_items=cart_items, total=total, phone=phone)


@main.route('/wishlist')
@login_required
def wishlist():
    raw = Wishlist.query.filter_by(user_id=current_user.id).all()
    items = []
    for it in raw:
        prod = Product.query.get(it.product_id)
        if not prod:
            prod = type('P', (), {'id': None, 'name': 'Unknown product', 'price': 0.0, 'image_url': '/static/img/default.jpg'})
        items.append(type('WI', (), {'id': it.id, 'product': prod}))
    return render_template('wishlist.html', items=items)


@main.route('/checkout', methods=['GET'])
@login_required
def checkout():
    # Pre-fill phone from user profile if available
    phone = getattr(current_user, 'phone', '')
    total = get_cart_total(current_user.id)
    return render_template('checkout.html', phone=phone, total=total)


@main.route("/add_product", methods=["GET", "POST"])
def add_product():
    form = ProductForm()

    if form.validate_on_submit():
        if form.image.data:
            # Secure the filename
            filename = secure_filename(form.image.data.filename)

            # Make sure uploads folder exists
            os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Save file to static/uploads
            form.image.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

            # Save URL relative to static folder
            image_url = f"/static/uploads/{filename}"
        else:
            image_url = "/static/img/default.jpg"

        # Add product to database
        new_product = Product(
            name=form.name.data,
            price=form.price.data,
            image_url=image_url   # <-- use the correct URL
        )

        db.session.add(new_product)
        db.session.commit()

        flash("Product added successfully!", "success")
        return redirect(url_for("main.shop"))

    return render_template("add_product.html", form=form)

 
 
@main.route("/remove_cart/<int:item_id>")
@login_required
def remove_cart(item_id):
    item = Cart.query.get(item_id)
    if item and item.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()
    return redirect("/cart")


@main.route("/remove_wishlist/<int:item_id>")
@login_required
def remove_wishlist(item_id):
    item = Wishlist.query.get(item_id)
    if item and item.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()
    return redirect("/wishlist")




def generate_billing_pdf(username, cart_items, total):
    filename = f"static/billing_pdfs/{username}_bill.pdf"

    # Ensure the directory exists before ReportLab writes the file
    dirpath = os.path.dirname(filename)
    try:
        os.makedirs(dirpath, exist_ok=True)
    except Exception:
        current_app.logger.exception('Failed to create billing_pdfs directory')

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(filename, pagesize=letter)

    story = []

    story.append(Paragraph("<b>Billing Receipt</b>", styles['Title']))
    story.append(Paragraph(f"Customer: {username}", styles['Normal']))

    for item in cart_items:
        story.append(Paragraph(
            f"{item.product.name} — {item.quantity} × Ksh {item.product.price} = Ksh {item.quantity * item.product.price}",
            styles['Normal']
        ))

    story.append(Paragraph(f"<b>Total: Ksh {total}</b>", styles['Heading2']))

    doc.build(story)

    return filename



@main.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in, send to homepage (avoid redirect loop)
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Welcome back!", "success")
            # honor optional `next` param to redirect after login
            next_page = request.args.get('next') or request.form.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for("main.home"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html", form=form)


@main.route('/__dev_login', methods=['POST'])
def dev_login():
    """Development helper: log in a user by email without CSRF/form.
    Enabled only when FLASK_ENV=development or ENABLE_DEV_ROUTES=1.
    Accepts JSON {"email": "..."} or form data.
    Returns JSON with success and user id.
    """
    if os.getenv('FLASK_ENV') != 'development' and os.getenv('ENABLE_DEV_ROUTES', '0') != '1':
        return jsonify({'message': 'Not allowed'}), 403

    data = request.get_json() or request.form
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    login_user(user)
    return jsonify({'message': 'Logged in', 'user_id': user.id}), 200



@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        # check existing email or username
        existing_user = User.query.filter(
            (User.email == form.email.data) |
            (User.username == form.username.data)
        ).first()

        if existing_user:
            flash("Email or username already exists.", "danger")
            return render_template('signup.html', form=form)

        # create user (normalize phone to canonical DB format)
        canonical = canonicalize_phone(form.phone.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            phone=canonical
        )
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Email or username already exists.", "danger")
            return render_template('signup.html', form=form)

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('main.login'))  # create login route later

    return render_template('signup.html', form=form)

@main.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()

    if form.validate_on_submit():
        # Save message or send email
        flash("Your message has been sent successfully!", "success")
        return redirect(url_for('main.contact'))

    return render_template('contact.html', form=form)



#----------------------------
# Send OTP
#----------------------------
@main.route("/send_otp", methods=["POST"])
def send_otp():
    from twilio.rest import Client
    from .models import VerificationCode
    from . import db
    import random

    # Get phone from request first
    data = request.get_json()
    phone = data.get("phone")
    if not phone:
        return jsonify({"success": False, "message": "Phone required"}), 400

    # Generate OTP code
    code = str(random.randint(100000, 999999))

    # Save in DB
    otp = VerificationCode(phone=phone, code=code)
    db.session.add(otp)
    db.session.commit()

    # Twilio credentials from environment
    ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
    AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
    TWILIO_NUMBER = os.getenv("TWILIO_NUMBER")

    if not ACCOUNT_SID or not AUTH_TOKEN or not TWILIO_NUMBER:
        # Log and return helpful error to caller (do not expose secrets)
        current_app.logger.error("Twilio credentials not configured in environment")
        return jsonify({"success": False, "message": "Server misconfigured: Twilio credentials missing"}), 500

    client = Client(ACCOUNT_SID, AUTH_TOKEN)

    try:
        message = client.messages.create(
            body=f"Your verification code is {code}",
            from_=TWILIO_NUMBER,
            to=phone
        )
        current_app.logger.info(f"Twilio Message SID: {message.sid}")
    except Exception as e:
        current_app.logger.exception("Twilio error while sending OTP")
        return jsonify({"success": False, "message": "Failed to send OTP"}), 500

    current_app.logger.debug(f"DEBUG OTP: {code}")  # for testing in console
    return jsonify({"success": True, "message": "OTP sent"}), 200



#----------------------------
# Verify OTP
#----------------------------
@main.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    phone = data.get("phone")
    code = data.get("code")

    if not phone or not code:
        return jsonify({"success": False, "message": "Missing"}), 400

    otp = VerificationCode.query.filter_by(phone=phone, code=code).order_by(VerificationCode.id.desc()).first()

    if not otp:
        return jsonify({"success": False, "message": "Invalid code"}), 400

    # models.VerificationCode.expiry uses naive UTC (datetime.utcnow()),
    # so compare with datetime.utcnow() to avoid naive/aware mismatch.
    if otp.expiry < datetime.utcnow():
        return jsonify({"success": False, "message": "Code expired"}), 400

    # Optionally delete the OTP so it can't be reused
    try:
        db.session.delete(otp)
        db.session.commit()
    except Exception:
        # don't fail verification if cleanup fails
        current_app.logger.exception("Failed to delete used OTP")

    return jsonify({"success": True, "message": "Verified"}), 200


@main.app_context_processor
def inject_counts():
    if current_user.is_authenticated:
        cart_count = Cart.query.filter_by(user_id=current_user.id).count()
        wishlist_count = Wishlist.query.filter_by(user_id=current_user.id).count()
    else:
        cart_count = 0
        wishlist_count = 0

    return dict(cart_count=cart_count, wishlist_count=wishlist_count)



@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("main.login"))
