import json
from app import db
from app.models import User, Product, Cart, PendingPayment, Order, OrderItem


def login_dev(client, email):
    # create user and login via dev route
    resp = client.post('/__dev_login', json={'email': email})
    return resp


def test_successful_mpesa_callback_creates_order(client, app):
    # create user
    with app.app_context():
        user = User(username='buyer', email='buyer@example.com', phone='254712345678')
        user.set_password('password')
        db.session.add(user)
        prod = Product(name='Shirt', price=500)
        db.session.add(prod)
        db.session.commit()
        user_id = user.id
        prod_id = prod.id

    # login as user using dev route
    client.post('/__dev_login', json={'email': 'buyer@example.com'})

    # add product to cart
    client.post(f'/add_to_cart/{prod_id}')

    # create a PendingPayment as if STK push was accepted
    with app.app_context():
        pending = PendingPayment(user_id=user_id, checkout_request_id='CR123', amount=500)
        db.session.add(pending)
        db.session.commit()

    # simulate callback
    payload = {
        'Body': {
            'stkCallback': {
                'MerchantRequestID': 'm1',
                'CheckoutRequestID': 'CR123',
                'ResultCode': 0,
                'ResultDesc': 'The service request is processed successfully.',
                'CallbackMetadata': {
                    'Item': [
                        {'Name': 'Amount', 'Value': 500},
                        {'Name': 'MpesaReceiptNumber', 'Value': 'RCPT123'},
                        {'Name': 'TransactionDate', 'Value': 20251203120000},
                        {'Name': 'PhoneNumber', 'Value': '254712345678'}
                    ]
                }
            }
        }
    }

    rv = client.post('/mpesa/callback', json=payload)
    assert rv.status_code == 200

    with app.app_context():
        o = Order.query.filter_by(user_id=user_id).first()
        assert o is not None
        assert o.status == 'paid'
        items = OrderItem.query.filter_by(order_id=o.id).all()
        assert len(items) == 1
        pending = PendingPayment.query.filter_by(checkout_request_id='CR123').first()
        assert pending.status == 'completed'


def test_failed_mpesa_callback_creates_rejected_order(client, app):
    # create user
    with app.app_context():
        user = User(username='buyer2', email='buyer2@example.com', phone='254712345679')
        user.set_password('password')
        db.session.add(user)
        prod = Product(name='Pants', price=800)
        db.session.add(prod)
        db.session.commit()
        user2_id = user.id
        prod2_id = prod.id

    # login and add to cart
    client.post('/__dev_login', json={'email': 'buyer2@example.com'})
    client.post(f'/add_to_cart/{prod2_id}')

    with app.app_context():
        pending = PendingPayment(user_id=user2_id, checkout_request_id='CR456', amount=800)
        db.session.add(pending)
        db.session.commit()

    payload = {
        'Body': {
            'stkCallback': {
                'MerchantRequestID': 'm2',
                'CheckoutRequestID': 'CR456',
                'ResultCode': 1,
                'ResultDesc': 'The transaction was cancelled by the user.',
                'CallbackMetadata': {}
            }
        }
    }

    rv = client.post('/mpesa/callback', json=payload)
    assert rv.status_code == 400

    with app.app_context():
        o = Order.query.filter_by(user_id=user2_id).first()
        assert o is not None
        assert o.status == 'rejected'
        pending = PendingPayment.query.filter_by(checkout_request_id='CR456').first()
        assert pending.status == 'failed'
