Twilio OTP setup
Twilio OTP setup

This project can send OTPs via Twilio. Follow these steps to configure and test:

1. Install dependencies:


2. Set the following environment variables (or create a `.env` file in the project root):


3. Run the Flask app as you normally do (for example with `flask run` or your WSGI server).

4. Test sending an OTP by POSTing JSON to `/send_otp`:


Notes:
- Do not commit your `.env` file or credentials to version control.
- Twilio charges may apply for sending messages to real phone numbers.

# Mitumba Apparel (Flask shop)

This repository contains a small Flask e-commerce (Mitumba Store) used for demos and testing. It includes:

- Product browsing and simple search
- Cart and wishlist functionality
- Signup/login with optional OTP (Twilio)
- Checkout via Safaricom M-Pesa STK push (sandbox integration)
- PendingPayment tracking and MPESA callback finalization
- Order and OrderItem models with PDF receipt generation
- Minimal admin views for orders and pending payments

## Quick start (development)

1. Create and activate a Python virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root and set required environment variables. Common variables used by the app:

- FLASK_ENV=development
- SECRET_KEY=<a secret key for Flask sessions>
- SQLALCHEMY_DATABASE_URI (optional; defaults to instance/mitumba.db)
- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_NUMBER (for Twilio OTP)
- MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET, MPESA_SHORTCODE, MPESA_PASSKEY, MPESA_CALLBACK_URL (for M-Pesa sandbox)

4. Run the app (development):

```bash
export FLASK_APP=wsgi.py
export FLASK_ENV=development
flask run
```

5. Open the site at http://127.0.0.1:5000

## Important notes

- The app will attempt to create DB tables automatically when running in development. For production use a proper migration workflow (Flask-Migrate / Alembic).
- An admin account `admin@admin.com` with password `admin123` is automatically created in development if it doesn't exist. Change this in production.
- Do not store secrets in source control. Use environment variables or a secrets manager.
- The M-Pesa integration targets the Safaricom sandbox — configure your sandbox credentials accordingly. The app saves MPESA audit payloads in `static/mpesa_logs` and generated receipts in `static/billing_pdfs`.

## Project structure (high level)

- `app/` - Flask application package
  - `models.py` - database models
  - `routes.py` - Flask routes, MPESA helpers and callbacks
  - `templates/` - HTML templates
- `instance/` - runtime data (default sqlite DB `mitumba.db`)
- `static/` - CSS, JS, images, MPESA audit logs and PDFs

## Tests

This repo contains a couple of pytest tests for the MPESA callback lifecycle. To run tests:

```bash
pytest -q
```

## Troubleshooting

- If you see errors on import related to circular imports, ensure you run the app via the `create_app()` factory (`wsgi.py` uses this pattern).
- If MPESA STK pushes return HTTP 400 from the sandbox: verify phone number format, use UTC timestamps and check sandbox credentials.

## Next steps / suggestions

- Add database migrations (Flask-Migrate) for production
- Add stronger test coverage around payment idempotency and callback handling
- Move secrets to a secure store for production

---
_This is sample/demo software. Use and adapt it as you need._
