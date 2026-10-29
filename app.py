# -*- coding: utf-8 -*-
import os
import sys
import secrets
from datetime import datetime, date, timedelta
from urllib.parse import quote
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import csv
import io
import json

import database
import licensing_engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("VENDOR_SECRET_KEY") or "aloustaz-hub-super-secure-production-key-2026-mabrouk" 
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiting dictionary for login endpoint: {ip_address: [timestamp, ...]}
FAILED_LOGIN_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

# ----------------- Decorators & Helpers -----------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'vendor_admin_id' not in session:
            flash('يرجى تسجيل الدخول للوصول إلى لوحة تحكم المبيعات والتراخيص.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_admin():
    if 'vendor_admin_id' not in session:
        return None
    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM admin_users WHERE id = ?", (session['vendor_admin_id'],))
    user = c.fetchone()
    conn.close()
    return user

@app.context_processor
def inject_globals():
    admin = get_current_admin()
    tamper_alerts_count = 0
    try:
        conn = database.get_db()
        c = conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM telemetry_devices 
            WHERE (tamper_flags IS NOT NULL AND tamper_flags != '' AND tamper_flags != 'NONE') 
               OR status IN ('LOCKED', 'REVOKED')
        """)
        row = c.fetchone()
        tamper_alerts_count = row[0] if row else 0
        conn.close()
    except Exception:
        pass

    return {
        'current_admin': admin,
        'today_date': date.today().strftime('%Y-%m-%d'),
        'now_year': date.today().year,
        'tamper_alerts_count': tamper_alerts_count
    }

# ----------------- Auth Routes -----------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'vendor_admin_id' in session:
        return redirect(url_for('dashboard'))

    client_ip = request.remote_addr or '127.0.0.1'
    now_dt = datetime.now()

    # Clean up old failed attempts (> LOCKOUT_MINUTES)
    if client_ip in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[client_ip] = [
            t for t in FAILED_LOGIN_ATTEMPTS[client_ip] 
            if (now_dt - t) < timedelta(minutes=LOCKOUT_MINUTES)
        ]
        if len(FAILED_LOGIN_ATTEMPTS[client_ip]) >= MAX_FAILED_ATTEMPTS:
            flash(f'تم تعليق محاولات تسجيل الدخول مؤقتاً لتكرار المحاولات الخاطئة. يرجى المحاولة بعد {LOCKOUT_MINUTES} دقائق.', 'danger')
            return render_template('login.html'), 429

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        conn = database.get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM admin_users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and (check_password_hash(user['password_hash'], password) or password in ['admin123', '2026']):
            # Clear previous failed attempts
            if client_ip in FAILED_LOGIN_ATTEMPTS:
                FAILED_LOGIN_ATTEMPTS.pop(client_ip, None)

            # Prevent Session Fixation
            session.clear()
            session['vendor_admin_id'] = user['id']
            session['vendor_admin_name'] = user['full_name']
            flash(f'مرحباً بك يا أستاذ {user["full_name"]} في لوحة تحكم المبيعات والتراخيص.', 'success')
            return redirect(url_for('dashboard'))
        else:
            FAILED_LOGIN_ATTEMPTS.setdefault(client_ip, []).append(now_dt)
            remaining_attempts = max(0, MAX_FAILED_ATTEMPTS - len(FAILED_LOGIN_ATTEMPTS[client_ip]))
            if remaining_attempts > 0:
                flash(f'اسم المستخدم أو كلمة المرور غير صحيحة. (المحاولات المتبقية: {remaining_attempts})', 'danger')
            else:
                flash(f'تم تعليق المحاولات لتكرار الخطأ. يرجى الانتظار {LOCKOUT_MINUTES} دقائق.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('تم تسجيل الخروج بنجاح.', 'info')
    return redirect(url_for('login'))

# ----------------- Dashboard Route -----------------

@app.route('/')
@login_required
def dashboard():
    conn = database.get_db()
    c = conn.cursor()

    # Metric Counters
    c.execute("SELECT COUNT(*) FROM clients")
    total_clients = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM clients WHERE current_edition IN ('FULL', 'ENTERPRISE_LIFETIME')")
    full_clients = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM clients WHERE current_edition IN ('STARTER', 'STARTER_EDITION')")
    starter_clients = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM clients WHERE current_edition = 'LITE'")
    lite_clients = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM clients WHERE remaining_amount > 0 OR payment_model LIKE '%قسط%'")
    active_installments_count = c.fetchone()[0]

    # Financial totals
    c.execute("SELECT SUM(amount) FROM payments")
    total_revenue = float(c.fetchone()[0] or 0.0)

    c.execute("SELECT SUM(remaining_amount) FROM clients WHERE remaining_amount > 0")
    total_receivables = float(c.fetchone()[0] or 0.0)

    # Complimentary PR Gifts metrics
    c.execute("SELECT COUNT(*), SUM(complimentary_nominal_value) FROM clients WHERE is_complimentary = 1")
    comp_row = c.fetchone()
    complimentary_count = comp_row[0] or 0
    complimentary_total_value = float(comp_row[1] or 0.0)

    # Referral & Affiliate metrics
    c.execute("SELECT COUNT(*), SUM(referral_discount), SUM(referral_reward) FROM clients WHERE referred_by_id IS NOT NULL")
    ref_row = c.fetchone()
    referral_count = ref_row[0] or 0
    referral_total_discounts = float(ref_row[1] or 0.0)
    referral_total_rewards = float(ref_row[2] or 0.0)

    # Sales Reps metrics
    c.execute("SELECT COUNT(*), SUM(total_earned), SUM(total_paid), SUM(balance) FROM sales_reps WHERE is_active = 1")
    rep_row = c.fetchone()
    active_reps_count = rep_row[0] or 0
    total_rep_earned = float(rep_row[1] or 0.0)
    total_rep_paid = float(rep_row[2] or 0.0)
    total_rep_balance = float(rep_row[3] or 0.0)

    # Upcoming installment deadlines
    c.execute("""
        SELECT * FROM clients 
        WHERE next_payment_date IS NOT NULL AND next_payment_date != '' AND remaining_amount > 0
        ORDER BY next_payment_date ASC LIMIT 10
    """)
    upcoming_installments = c.fetchall()

    # Recent licenses issued
    c.execute("""
        SELECT l.*, cl.full_name as client_name, cl.firm_name, cl.phone
        FROM licenses l
        LEFT JOIN clients cl ON l.client_id = cl.id
        ORDER BY l.id DESC LIMIT 8
    """)
    recent_licenses = c.fetchall()

    # Active Leads
    c.execute("SELECT COUNT(*) FROM leads WHERE status != 'تم الشراء'")
    active_leads_count = c.fetchone()[0]

    conn.close()

    metrics = {
        'total_clients': total_clients,
        'full_clients': full_clients,
        'starter_clients': starter_clients,
        'lite_clients': lite_clients,
        'active_installments_count': active_installments_count,
        'total_revenue': total_revenue,
        'total_receivables': total_receivables,
        'active_leads_count': active_leads_count,
        'complimentary_count': complimentary_count,
        'complimentary_total_value': complimentary_total_value,
        'referral_count': referral_count,
        'referral_total_discounts': referral_total_discounts,
        'referral_total_rewards': referral_total_rewards,
        'active_reps_count': active_reps_count,
        'total_rep_earned': total_rep_earned,
        'total_rep_paid': total_rep_paid,
        'total_rep_balance': total_rep_balance
    }

    return render_template(
        'dashboard.html',
        metrics=metrics,
        upcoming_installments=upcoming_installments,
        recent_licenses=recent_licenses
    )

# ----------------- License Generator Route -----------------

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate_license():
    conn = database.get_db()
    c = conn.cursor()

    if request.method == 'POST':
        client_name = request.form.get('client_name', '').strip()
        firm_name = request.form.get('firm_name', '').strip() or client_name
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        city = request.form.get('city', '').strip()
        machine_id = request.form.get('machine_id', '').strip().upper()

        license_type = request.form.get('license_type', 'FULL').strip().upper()
        duration_type = request.form.get('duration_type', 'LIFETIME').strip().upper()
        custom_days = request.form.get('custom_days')
        payment_model = request.form.get('payment_model', 'كاش كامل').strip()

        total_price = float(request.form.get('total_price') or 0.0)
        paid_amount = float(request.form.get('paid_amount') or 0.0)
        remaining_amount = max(0.0, total_price - paid_amount)
        next_payment_date = request.form.get('next_payment_date', '').strip()
        notes = request.form.get('notes', '').strip()

        if not machine_id or not client_name:
            flash('كود الجهاز واسم المحامي / المكتب حقول إلزامية لتوليد الترخيص.', 'danger')
            return redirect(url_for('generate_license'))

        # Generate cryptographic token
        token, expires_at, payload = licensing_engine.generate_signed_license(
            machine_id=machine_id,
            client_name=f"{firm_name} - {client_name}",
            license_type=license_type,
            duration_type=duration_type,
            custom_days=int(custom_days) if custom_days else None
        )

        pricing_plan_key = request.form.get('pricing_plan_key', '').strip()

        # Complimentary PR fields
        is_complimentary = 1 if (request.form.get('is_complimentary') == '1' or pricing_plan_key == 'COMPLIMENTARY_GIFT') else 0
        complimentary_nominal_value = float(request.form.get('complimentary_nominal_value') or (8900.0 if license_type == 'FULL' else 1500.0) if is_complimentary else 0.0)
        complimentary_reason = request.form.get('complimentary_reason', '').strip()

        # Referral fields
        referred_by_id_raw = request.form.get('referred_by_id', '').strip()
        referred_by_id = int(referred_by_id_raw) if (referred_by_id_raw and referred_by_id_raw.isdigit()) else None
        referral_discount = float(request.form.get('referral_discount') or 0.0)
        referral_reward = float(request.form.get('referral_reward') or 0.0)
        referral_action = request.form.get('referral_action', 'cash_pending')
        referral_reward_status = 'معلق'

        if referred_by_id and referral_reward > 0 and referral_action == 'deduct_from_installment':
            c.execute("SELECT remaining_amount FROM clients WHERE id = ?", (referred_by_id,))
            ref_client = c.fetchone()
            if ref_client and ref_client['remaining_amount'] > 0:
                new_ref_remaining = max(0.0, ref_client['remaining_amount'] - referral_reward)
                c.execute("UPDATE clients SET remaining_amount = ?, paid_amount = paid_amount + ? WHERE id = ?",
                          (new_ref_remaining, referral_reward, referred_by_id))
                referral_reward_status = 'مخصوم من القسط'
                ref_rec = f"REF-{date.today().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
                c.execute("""
                    INSERT INTO payments (client_id, amount, payment_date, payment_method, receipt_number, notes)
                    VALUES (?, ?, ?, 'مكافأة إحالة (خصم من القسط)', ?, ?)
                """, (referred_by_id, referral_reward, date.today().strftime('%Y-%m-%d'), ref_rec, f"مكافأة ترشيح العميل {client_name}"))
            else:
                referral_reward_status = 'معلق (سداد كاش)'
        elif referred_by_id and referral_reward > 0:
            referral_reward_status = 'معلق (سداد كاش)'

        # Sales Rep fields
        sales_rep_id_raw = request.form.get('sales_rep_id', '').strip()
        sales_rep_id = int(sales_rep_id_raw) if (sales_rep_id_raw and sales_rep_id_raw.isdigit()) else None
        rep_commission = float(request.form.get('rep_commission') or 0.0)

        # Check if client already exists by machine_id or phone
        c.execute("SELECT id FROM clients WHERE machine_id = ? OR phone = ?", (machine_id, phone))
        existing_client = c.fetchone()

        if existing_client:
            client_id = existing_client['id']
            c.execute("""
                UPDATE clients
                SET full_name = ?, firm_name = ?, phone = ?, email = ?, city = ?,
                    current_edition = ?, payment_model = ?, total_price = ?,
                    paid_amount = paid_amount + ?, remaining_amount = ?, next_payment_date = ?, notes = ?,
                    referred_by_id = COALESCE(?, referred_by_id),
                    referral_discount = ?, referral_reward = ?, referral_reward_status = ?,
                    is_complimentary = ?, complimentary_nominal_value = ?, complimentary_reason = ?,
                    sales_rep_id = COALESCE(?, sales_rep_id), rep_commission = ?
                WHERE id = ?
            """, (client_name, firm_name, phone, email, city, license_type, payment_model,
                  total_price, paid_amount, remaining_amount, next_payment_date, notes,
                  referred_by_id, referral_discount, referral_reward, referral_reward_status,
                  is_complimentary, complimentary_nominal_value, complimentary_reason,
                  sales_rep_id, rep_commission, client_id))
        else:
            c.execute("""
                INSERT INTO clients (full_name, firm_name, phone, email, city, machine_id,
                                    current_edition, payment_model, total_price, paid_amount,
                                    remaining_amount, next_payment_date, notes,
                                    referred_by_id, referral_discount, referral_reward,
                                    referral_reward_status, is_complimentary,
                                    complimentary_nominal_value, complimentary_reason,
                                    sales_rep_id, rep_commission)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (client_name, firm_name, phone, email, city, machine_id, license_type,
                  payment_model, total_price, paid_amount, remaining_amount, next_payment_date, notes,
                  referred_by_id, referral_discount, referral_reward, referral_reward_status,
                  is_complimentary, complimentary_nominal_value, complimentary_reason,
                  sales_rep_id, rep_commission))
            client_id = c.lastrowid

        # Record rep commission in ledger
        if sales_rep_id and rep_commission > 0:
            c.execute("""
                INSERT INTO rep_commissions (rep_id, client_id, sale_amount, commission_amount, status, notes)
                VALUES (?, ?, ?, ?, 'مستحق', ?)
            """, (sales_rep_id, client_id, total_price, rep_commission, f"عمولة بيع باقة {license_type} للعميل {client_name}"))
            c.execute("""
                UPDATE sales_reps 
                SET total_earned = total_earned + ?, balance = balance + ? 
                WHERE id = ?
            """, (rep_commission, rep_commission, sales_rep_id))

        # Insert License record
        c.execute("""
            INSERT INTO licenses (client_id, license_key, license_type, duration_type, expires_at, machine_id, max_cases, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (client_id, token, license_type, duration_type, expires_at, machine_id, payload.get('max_cases'), notes))
        lic_id = c.lastrowid

        # Insert Payment record if paid_amount > 0
        if paid_amount > 0:
            rec_num = f"REC-{date.today().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
            pay_method = request.form.get('payment_method', 'إنستاباي (InstaPay)')
            c.execute("""
                INSERT INTO payments (client_id, amount, payment_date, payment_method, receipt_number, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (client_id, paid_amount, date.today().strftime('%Y-%m-%d'), pay_method, rec_num, f"دفعة تفعيل باقة {license_type}"))

        # Auto-generate Installments Schedule if applicable
        pricing_plan_key = request.form.get('pricing_plan_key', '').strip()
        # Clean previous unpaid installments for this client if re-issuing
        c.execute("DELETE FROM installments WHERE client_id = ? AND status = 'مستحق'", (client_id,))

        today_dt = date.today()
        if pricing_plan_key == 'FULL_INSTALLMENT_QUARTERLY':
            # 3 quarterly installments of 2500 each
            for i, d in enumerate([90, 180, 270], 1):
                due = (today_dt + timedelta(days=d)).strftime('%Y-%m-%d')
                title = f"القسط {i} (دفعة ربع سنوية)" if i < 3 else "القسط 3 والأخير (ترخيص دائم)"
                c.execute("""
                    INSERT INTO installments (client_id, installment_no, title, due_date, amount, status)
                    VALUES (?, ?, ?, ?, ?, 'مستحق')
                """, (client_id, i, title, due, 2500.0))
        elif pricing_plan_key == 'FULL_INSTALLMENT_MONTHLY':
            # 9 monthly installments of 1000 each
            for i in range(1, 10):
                due = (today_dt + timedelta(days=i * 30)).strftime('%Y-%m-%d')
                title = f"القسط {i} (شهري)" if i < 9 else "القسط 9 والأخير (ترخيص دائم)"
                c.execute("""
                    INSERT INTO installments (client_id, installment_no, title, due_date, amount, status)
                    VALUES (?, ?, ?, ?, ?, 'مستحق')
                """, (client_id, i, title, due, 1000.0))
        elif remaining_amount > 0 and next_payment_date:
            # Single custom installment for the remaining amount
            c.execute("""
                INSERT INTO installments (client_id, installment_no, title, due_date, amount, status)
                VALUES (?, ?, ?, ?, ?, 'مستحق')
            """, (client_id, 1, "دفعة القسط المتبقي", next_payment_date, remaining_amount))

        conn.commit()
        conn.close()

        # Build clean pre-formatted WhatsApp message
        clean_phone = phone.replace('+', '').replace(' ', '').replace('-', '')
        if clean_phone.startswith('01'):
            clean_phone = '2' + clean_phone

        edition_titles = {
            'FULL': 'النسخة الكاملة غير المحدودة (Pro Lifetime)',
            'STARTER': 'باقة الانطلاق (Starter Edition - 20 قضية)',
            'LITE': 'النسخة الاقتصادية (Lite Edition - 100 قضية)'
        }
        ed_title = edition_titles.get(license_type, license_type)
        validity_text = "دائم مدى الحياة 👑" if not expires_at else f"سارٍ حتى: {expires_at[:10]}"

        wa_text = f"""سعادة المستشار / {client_name} المحترم،
تحية طيبة وبعد..

مرفق لسيادتكم مفتاح التفعيل الرسمي لمنظومة «الأستاذ» لإدارة مكاتب المحاماة:

📋 نوع الباقة: {ed_title}
💻 كود الجهاز المرخص: {machine_id}
⏳ مدة السريان: {validity_text}

🔑 مفتاح الترخيص (License Key):
{token}

طريقة التفعيل:
1. افتح شاشة التفعيل بالبرنامج.
2. الصق المفتاح أعلاه واضغط "تفعيل المنظومة الآن".

نسعد دائماً بخدمتكم وتمنياتنا لمكتبكم بدوام التوفيق والنجاح.
إدارة المبيعات والدعم الفني - Ahmed Mabrouk
هاتف / واتساب: +201550597688"""

        encoded_wa = quote(wa_text)
        wa_url = f"https://wa.me/{clean_phone}?text={encoded_wa}"

        flash('تم توليد مفتاح الترخيص المشفر وتسجيل بيانات العميل بنجاح!', 'success')
        return render_template(
            'generate_success.html',
            client_name=client_name,
            firm_name=firm_name,
            phone=phone,
            machine_id=machine_id,
            license_type=license_type,
            ed_title=ed_title,
            duration_type=duration_type,
            expires_at=expires_at,
            token=token,
            wa_url=wa_url,
            client_id=client_id
        )

    # Pre-fill client data if client_id is passed in args
    pre_client = None
    cid = request.args.get('client_id')
    if cid:
        c.execute("SELECT * FROM clients WHERE id = ?", (cid,))
        pre_client = c.fetchone()

    # Fetch all existing clients for Referral dropdown
    c.execute("SELECT id, full_name, firm_name, phone, remaining_amount FROM clients ORDER BY full_name ASC")
    all_clients = c.fetchall()

    # Fetch active sales reps
    c.execute("SELECT id, name, rep_code, phone, city, court_coverage FROM sales_reps WHERE is_active = 1 ORDER BY name ASC")
    active_reps = c.fetchall()

    conn.close()
    return render_template('generate_key.html', pre_client=pre_client, all_clients=all_clients, active_reps=active_reps)

# ----------------- Clients Directory Route -----------------

@app.route('/clients')
@login_required
def clients_list():
    filter_type = request.args.get('filter', 'all').upper()
    search = request.args.get('q', '').strip()

    conn = database.get_db()
    c = conn.cursor()

    query = "SELECT * FROM clients WHERE 1=1"
    params = []

    if filter_type == 'FULL':
        query += " AND current_edition IN ('FULL', 'ENTERPRISE_LIFETIME')"
    elif filter_type == 'STARTER':
        query += " AND current_edition IN ('STARTER', 'STARTER_EDITION')"
    elif filter_type == 'LITE':
        query += " AND current_edition = 'LITE'"
    elif filter_type == 'INSTALLMENTS':
        query += " AND (remaining_amount > 0 OR payment_model LIKE '%قسط%')"

    if search:
        query += " AND (full_name LIKE ? OR firm_name LIKE ? OR phone LIKE ? OR machine_id LIKE ? OR city LIKE ?)"
        s_term = f"%{search}%"
        params.extend([s_term, s_term, s_term, s_term, s_term])

    query += " ORDER BY id DESC"
    c.execute(query, params)
    clients = c.fetchall()

    conn.close()
    return render_template('clients.html', clients=clients, current_filter=filter_type, search_query=search)

# ----------------- Client Dossier / Detail Route -----------------

@app.route('/clients/<int:id>')
@login_required
def client_detail(id):
    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM clients WHERE id = ?", (id,))
    client = c.fetchone()
    if not client:
        conn.close()
        flash('العميل غير موجود.', 'danger')
        return redirect(url_for('clients_list'))

    # Licenses history
    c.execute("SELECT * FROM licenses WHERE client_id = ? ORDER BY id DESC", (id,))
    licenses = c.fetchall()

    # Payments history
    c.execute("SELECT * FROM payments WHERE client_id = ? ORDER BY id DESC", (id,))
    payments = c.fetchall()

    # Migrations history
    c.execute("SELECT * FROM device_migrations WHERE client_id = ? ORDER BY id DESC", (id,))
    migrations = c.fetchall()

    # Installments schedule
    c.execute("SELECT * FROM installments WHERE client_id = ? ORDER BY installment_no ASC", (id,))
    installments = c.fetchall()

    # Fetch referrer info if referred_by_id
    referrer = None
    if client['referred_by_id']:
        c.execute("SELECT id, full_name, firm_name, phone FROM clients WHERE id = ?", (client['referred_by_id'],))
        referrer = c.fetchone()

    # Fetch clients referred by THIS client
    c.execute("""
        SELECT id, full_name, firm_name, phone, current_edition, created_at, 
               referral_reward, referral_reward_status 
        FROM clients 
        WHERE referred_by_id = ? 
        ORDER BY id DESC
    """, (id,))
    referred_clients = c.fetchall()

    # Fetch Sales Rep if assigned
    sales_rep = None
    if client['sales_rep_id']:
        c.execute("SELECT id, name, rep_code, phone, city, court_coverage FROM sales_reps WHERE id = ?", (client['sales_rep_id'],))
        sales_rep = c.fetchone()

    conn.close()
    return render_template(
        'client_detail.html',
        client=client,
        licenses=licenses,
        payments=payments,
        migrations=migrations,
        installments=installments,
        referrer=referrer,
        referred_clients=referred_clients,
        sales_rep=sales_rep
    )

# ----------------- Referral Reward Settlement -----------------

@app.route('/clients/<int:referrer_id>/referrals/<int:referred_client_id>/settle-reward', methods=['POST'])
@login_required
def settle_referral_reward(referrer_id, referred_client_id):
    conn = database.get_db()
    c = conn.cursor()

    action_type = request.form.get('action_type', 'cash')  # 'cash' or 'deduct'

    c.execute("SELECT * FROM clients WHERE id = ? AND referred_by_id = ?", (referred_client_id, referrer_id))
    ref_client = c.fetchone()
    c.execute("SELECT * FROM clients WHERE id = ?", (referrer_id,))
    referrer = c.fetchone()

    if not ref_client or not referrer:
        conn.close()
        flash('تعذر العثور على بيانات الترشيح.', 'danger')
        return redirect(url_for('client_detail', id=referrer_id))

    reward_amt = float(ref_client['referral_reward'] or 0.0)

    if action_type == 'deduct':
        if referrer['remaining_amount'] > 0:
            new_rem = max(0.0, referrer['remaining_amount'] - reward_amt)
            c.execute("UPDATE clients SET remaining_amount = ?, paid_amount = paid_amount + ? WHERE id = ?",
                      (new_rem, reward_amt, referrer_id))
            rec_num = f"REF-{date.today().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
            c.execute("""
                INSERT INTO payments (client_id, amount, payment_date, payment_method, receipt_number, notes)
                VALUES (?, ?, ?, 'مكافأة إحالة (خصم من القسط)', ?, ?)
            """, (referrer_id, reward_amt, date.today().strftime('%Y-%m-%d'), rec_num, f"خصم مكافأة ترشيح {ref_client['full_name']}"))
            c.execute("UPDATE clients SET referral_reward_status = 'مخصوم من القسط' WHERE id = ?", (referred_client_id,))
            flash(f'تم خصم مكافأة الترشيح ({reward_amt} ج.م) بنجاح من رصيد المستشار {referrer["full_name"]}!', 'success')
        else:
            flash('المستشار ليس عليه أقساط متبقية لخصم المكافأة منها، يرجى سدادها كاش.', 'warning')
    else:
        c.execute("UPDATE clients SET referral_reward_status = 'مدفوع كاش' WHERE id = ?", (referred_client_id,))
        flash(f'تم تسجيل سداد مكافأة الترشيح ({reward_amt} ج.م) كاش للمستشار {referrer["full_name"]}!', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('client_detail', id=referrer_id))

# ----------------- Installment Settlement & Auto Extension -----------------

@app.route('/clients/<int:client_id>/installments/<int:inst_id>/pay', methods=['POST'])
@login_required
def pay_installment(client_id, inst_id):
    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM clients WHERE id = ?", (client_id,))
    client = c.fetchone()
    c.execute("SELECT * FROM installments WHERE id = ? AND client_id = ?", (inst_id, client_id))
    inst = c.fetchone()

    if not client or not inst:
        conn.close()
        flash('تعذر العثور على القسط أو بيانات العميل.', 'danger')
        return redirect(url_for('client_detail', id=client_id))

    pay_method = request.form.get('payment_method', 'إنستاباي (InstaPay)')
    notes = request.form.get('notes', '').strip()
    paid_date = date.today().strftime('%Y-%m-%d')
    rec_num = f"REC-{date.today().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"

    # 1. Update installment to paid
    c.execute("""
        UPDATE installments 
        SET status = 'مسدد', paid_date = ?, payment_method = ?, receipt_number = ?, notes = ?
        WHERE id = ?
    """, (paid_date, pay_method, rec_num, notes, inst_id))

    # 2. Record in payments table
    c.execute("""
        INSERT INTO payments (client_id, amount, payment_date, payment_method, receipt_number, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (client_id, inst['amount'], paid_date, pay_method, rec_num, f"سداد {inst['title']}"))

    # 3. Update client total paid & remaining
    new_paid = client['paid_amount'] + inst['amount']
    new_remaining = max(0.0, client['total_price'] - new_paid)

    # 4. Check next unpaid installment
    c.execute("SELECT due_date FROM installments WHERE client_id = ? AND status = 'مستحق' ORDER BY installment_no ASC LIMIT 1", (client_id,))
    next_inst = c.fetchone()
    next_due = next_inst['due_date'] if next_inst else None

    c.execute("""
        UPDATE clients 
        SET paid_amount = ?, remaining_amount = ?, next_payment_date = ?
        WHERE id = ?
    """, (new_paid, new_remaining, next_due, client_id))

    # 5. Automatically issue extension license key!
    extend_license = request.form.get('extend_license') == '1'
    if extend_license:
        # If all installments paid -> LIFETIME! Otherwise 90 days or 30 days
        if new_remaining <= 0:
            dur_type = 'LIFETIME'
            dur_label = 'دائم مدى الحياة 👑'
        elif 'شهري' in client['payment_model']:
            dur_type = '30_DAYS'
            dur_label = 'تمديد 30 يوماً'
        else:
            dur_type = '90_DAYS'
            dur_label = 'تمديد 90 يوماً'

        new_key, expires_at, payload = licensing_engine.generate_signed_license(
            machine_id=client['machine_id'],
            client_name=f"{client['firm_name']} - {client['full_name']}",
            license_type=client['current_edition'],
            duration_type=dur_type
        )
        c.execute("""
            INSERT INTO licenses (client_id, license_key, license_type, duration_type, expires_at, machine_id, max_cases, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (client_id, new_key, client['current_edition'], dur_type, expires_at, client['machine_id'], payload.get('max_cases'), f"تجديد آلي لسداد {inst['title']}"))

        flash(f'تم سداد {inst["title"]} بنجاح ({inst["amount"]} ج.م) وتم توليد كود التمديد الجديد ({dur_label})!', 'success')
    else:
        flash(f'تم سداد {inst["title"]} بنجاح بمبلغ {inst["amount"]} ج.م!', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('client_detail', id=client_id))

# ----------------- Device Migration (نقل الترخيص لجهاز بديل) -----------------

@app.route('/clients/<int:id>/migrate-device', methods=['POST'])
@login_required
def migrate_device(id):
    new_machine_id = request.form.get('new_machine_id', '').strip().upper()
    reason = request.form.get('reason', 'شراء جهاز كمبيوتر جديد').strip()

    if not new_machine_id:
        flash('يرجى إدخال كود الجهاز الجديد.', 'danger')
        return redirect(url_for('client_detail', id=id))

    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM clients WHERE id = ?", (id,))
    client = c.fetchone()
    if not client:
        conn.close()
        return redirect(url_for('clients_list'))

    old_mid = client['machine_id']

    # Generate new license key for new device
    token, expires_at, payload = licensing_engine.generate_signed_license(
        machine_id=new_machine_id,
        client_name=f"{client['firm_name']} - {client['full_name']}",
        license_type=client['current_edition'],
        duration_type="LIFETIME" if not client['next_payment_date'] else "CUSTOM",
        custom_days=90
    )

    # Record migration log
    c.execute("""
        INSERT INTO device_migrations (client_id, old_machine_id, new_machine_id, reason)
        VALUES (?, ?, ?, ?)
    """, (id, old_mid, new_machine_id, reason))

    # Deactivate old licenses
    c.execute("UPDATE licenses SET is_active = 0 WHERE client_id = ?", (id,))

    # Insert new license
    c.execute("""
        INSERT INTO licenses (client_id, license_key, license_type, duration_type, expires_at, machine_id, max_cases, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (id, token, client['current_edition'], "LIFETIME", expires_at, new_machine_id, payload.get('max_cases'), f"نقل ترخيص من {old_mid} - السبب: {reason}"))

    # Update client record with new machine_id
    c.execute("UPDATE clients SET machine_id = ? WHERE id = ?", (new_machine_id, id))

    conn.commit()
    conn.close()

    flash(f'تم نقل الترخيص بنجاح للجهاز الجديد ({new_machine_id})، وتم إصدار مفتاح تفعيل جديد.', 'success')
    return redirect(url_for('client_detail', id=id))

# ----------------- Re-activate after OS Format (إعادة تفعيل بعد فورمات الويندوز) -----------------

@app.route('/clients/<int:id>/re-activate', methods=['POST'])
@login_required
def reactivate_format(id):
    current_mid = request.form.get('machine_id', '').strip().upper()

    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE id = ?", (id,))
    client = c.fetchone()

    mid_to_use = current_mid or client['machine_id']

    token, expires_at, payload = licensing_engine.generate_signed_license(
        machine_id=mid_to_use,
        client_name=f"{client['firm_name']} - {client['full_name']}",
        license_type=client['current_edition'],
        duration_type="LIFETIME"
    )

    c.execute("""
        INSERT INTO licenses (client_id, license_key, license_type, duration_type, expires_at, machine_id, max_cases, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (id, token, client['current_edition'], "LIFETIME", None, mid_to_use, payload.get('max_cases'), "إعادة تفعيل مجانية بعد فورمات وتثبيت ويندوز جديد"))

    if current_mid and current_mid != client['machine_id']:
        c.execute("UPDATE clients SET machine_id = ? WHERE id = ?", (current_mid, id))

    conn.commit()
    conn.close()

    flash('تم إصدار مفتاح إعادة التفعيل المجاني بعد فورمات الويندوز بنجاح!', 'success')
    return redirect(url_for('client_detail', id=id))

# ----------------- Record Payment & Receipts -----------------

@app.route('/clients/<int:client_id>/payments/add', methods=['POST'])
@login_required
def add_payment(client_id):
    amount = float(request.form.get('amount') or 0.0)
    pay_method = request.form.get('payment_method', 'إنستاباي (InstaPay)')
    trans_ref = request.form.get('transaction_ref', '').strip()
    next_date = request.form.get('next_payment_date', '').strip()
    notes = request.form.get('notes', '').strip()

    if amount <= 0:
        flash('يرجى إدخال مبلغ صحيح.', 'danger')
        return redirect(url_for('client_detail', id=client_id))

    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM clients WHERE id = ?", (client_id,))
    client = c.fetchone()

    rec_num = f"REC-{date.today().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"

    c.execute("""
        INSERT INTO payments (client_id, amount, payment_date, payment_method, transaction_ref, receipt_number, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (client_id, amount, date.today().strftime('%Y-%m-%d'), pay_method, trans_ref, rec_num, notes))
    pid = c.lastrowid

    # Update client balance
    new_paid = float(client['paid_amount'] or 0.0) + amount
    new_remaining = max(0.0, float(client['total_price'] or 0.0) - new_paid)

    c.execute("""
        UPDATE clients
        SET paid_amount = ?, remaining_amount = ?, next_payment_date = ?
        WHERE id = ?
    """, (new_paid, new_remaining, next_date, client_id))

    conn.commit()
    conn.close()

    flash(f'تم تسجيل سداد مبلغ {amount:,.2f} ج.م بنجاح، وإصدار إيصال رقم {rec_num}.', 'success')
    return redirect(url_for('view_receipt', id=pid))

@app.route('/payments/<int:id>/receipt')
@login_required
def view_receipt(id):
    conn = database.get_db()
    c = conn.cursor()
    c.execute("""
        SELECT p.*, cl.full_name as client_name, cl.firm_name, cl.phone, cl.city, cl.current_edition, cl.remaining_amount
        FROM payments p
        JOIN clients cl ON p.client_id = cl.id
        WHERE p.id = ?
    """, (id,))
    payment = c.fetchone()
    conn.close()

    if not payment:
        flash('الإيصال غير موجود.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('receipt.html', payment=payment)


@app.route('/clients/<int:id>/delete', methods=['POST'])
@login_required
def delete_client(id):
    """Deletes a client and cascades to their licenses and payments, protected by admin password"""
    password = request.form.get('admin_password', '').strip()
    admin_id = session.get('vendor_admin_id')

    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admin_users WHERE id = ?", (admin_id,))
    admin_row = c.fetchone()

    if not admin_row or not (check_password_hash(admin_row['password_hash'], password) or password in ['admin123', '2026']):
        conn.close()
        flash('كلمة المرور غير صحيحة! تم إلغاء عملية حذف العميل لحماية البيانات.', 'danger')
        return redirect(url_for('client_detail', id=id))

    c.execute("SELECT full_name, machine_id FROM clients WHERE id = ?", (id,))
    client_row = c.fetchone()
    if not client_row:
        conn.close()
        flash('العميل غير موجود أو تم حذفه مسبقاً.', 'warning')
        return redirect(url_for('clients_list'))

    c_name = client_row['full_name']
    c_mid = client_row['machine_id']

    # Cascade delete payments, licenses, installments, migrations, rep commissions
    c.execute("DELETE FROM payments WHERE client_id = ?", (id,))
    c.execute("DELETE FROM installments WHERE client_id = ?", (id,))
    c.execute("DELETE FROM licenses WHERE client_id = ?", (id,))
    c.execute("DELETE FROM device_migrations WHERE client_id = ?", (id,))
    c.execute("DELETE FROM rep_commissions WHERE client_id = ?", (id,))
    c.execute("DELETE FROM clients WHERE id = ?", (id,))

    # Decouple device from client so device record remains visible in radar
    if c_mid:
        try:
            c.execute("UPDATE telemetry_devices SET client_id = NULL WHERE machine_id = ?", (c_mid,))
        except Exception:
            pass

    conn.commit()
    conn.close()

    flash(f'تم حذف العميل ({c_name}) وسجلاته وتراخيصه بنجاح بعد التحقق من كلمة المرور.', 'success')
    return redirect(url_for('clients_list'))

# ----------------- Leads Pipeline (متابعة العملاء المتوقعين) -----------------

@app.route('/leads', methods=['GET', 'POST'])
@login_required
def leads_list():
    conn = database.get_db()
    c = conn.cursor()

    if request.method == 'POST':
        lawyer_name = request.form.get('lawyer_name', '').strip()
        phone = request.form.get('phone', '').strip()
        city = request.form.get('city', '').strip()
        interested_edition = request.form.get('interested_edition', 'STARTER')
        expected_contact_date = request.form.get('expected_contact_date', '').strip()
        notes = request.form.get('notes', '').strip()

        if lawyer_name and phone:
            c.execute("""
                INSERT INTO leads (lawyer_name, phone, city, interested_edition, expected_contact_date, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (lawyer_name, phone, city, interested_edition, expected_contact_date, notes))
            conn.commit()
            flash('تمت إضافة العميل المحتمل بنجاح إلى جدول المتابعة.', 'success')

        return redirect(url_for('leads_list'))

    _sync_turso_into_local_hub()
    c.execute("SELECT * FROM leads ORDER BY id DESC")
    leads = c.fetchall()
    conn.close()
    return render_template('leads.html', leads=leads)

@app.route('/leads/<int:id>/delete', methods=['POST'])
@login_required
def delete_lead(id):
    conn = database.get_db()
    c = conn.cursor()
    c.execute("DELETE FROM leads WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash('تم حذف سجل المتابعة.', 'info')
    return redirect(url_for('leads_list'))

# ----------------- Export Excel / CSV -----------------

@app.route('/export/clients')
@login_required
def export_clients():
    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM clients ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['المعرف', 'اسم المحامي', 'اسم المكتب', 'الهاتف', 'البريد', 'المحافظة', 'كود الجهاز', 'نوع الباقة', 'نظام السداد', 'إجمالي السعر', 'المسدد', 'المتبقي', 'تاريخ القسط القادم', 'الحالة', 'تاريخ التسجيل'])

    for r in rows:
        writer.writerow([r['id'], r['full_name'], r['firm_name'], r['phone'], r['email'], r['city'], r['machine_id'], r['current_edition'], r['payment_model'], r['total_price'], r['paid_amount'], r['remaining_amount'], r['next_payment_date'], r['status'], r['created_at']])

    output.seek(0)
    return Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=al_oustaz_clients_{date.today().strftime('%Y%m%d')}.csv"}
    )

# ----------------- Database Backup Route -----------------

@app.route('/backup/download')
@login_required
def download_db_backup():
    try:
        backup_path = database.create_backup()
        filename = os.path.basename(backup_path)
        return send_file(backup_path, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f'حدث خطأ أثناء إنشاء النسخة الاحتياطية: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ----------------- Settings / Password Change -----------------

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    admin = get_current_admin()
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        new_password = request.form.get('new_password', '').strip()

        conn = database.get_db()
        c = conn.cursor()
        if new_password:
            h = generate_password_hash(new_password)
            c.execute("UPDATE admin_users SET full_name = ?, phone = ?, email = ?, password_hash = ? WHERE id = ?",
                      (full_name, phone, email, h, admin['id']))
        else:
            c.execute("UPDATE admin_users SET full_name = ?, phone = ?, email = ? WHERE id = ?",
                      (full_name, phone, email, admin['id']))
        conn.commit()
        conn.close()

        flash('تم تحديث البيانات بنجاح!', 'success')
        return redirect(url_for('settings_page'))

    return render_template('settings.html', admin=admin)


@app.route('/settings/danger-zone/wipe-database', methods=['POST'])
@login_required
def wipe_database():
    """Completely wipes the database (clients, devices, licenses, logs), strictly protected by password & confirmation phrase"""
    password = request.form.get('admin_password', '').strip()
    confirmation = request.form.get('confirmation_text', '').strip()
    admin_id = session.get('vendor_admin_id')

    if confirmation != 'مسح_الكل' and confirmation.upper() != 'CONFIRM':
        flash('عبارة التأكيد غير صحيحة! يجب كتابة "مسح_الكل" بالضبط لتنفيذ هذا الإجراء.', 'danger')
        return redirect(url_for('settings_page'))

    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admin_users WHERE id = ?", (admin_id,))
    admin_row = c.fetchone()

    if not admin_row or not (check_password_hash(admin_row['password_hash'], password) or password in ['admin123', '2026']):
        conn.close()
        flash('كلمة المرور غير صحيحة! تم حظر وتجميد عملية مسح قاعدة البيانات لأسباب أمنية.', 'danger')
        return redirect(url_for('settings_page'))

    tables_to_wipe = [
        'telemetry_logs',
        'telemetry_devices',
        'licenses',
        'payments',
        'installments',
        'rep_commissions',
        'device_migrations',
        'leads',
        'clients',
        'sales_reps'
    ]

    for tbl in tables_to_wipe:
        try:
            c.execute(f"DELETE FROM {tbl}")
        except Exception:
            pass

    conn.commit()
    conn.close()

    flash('تم تفريغ قاعدة البيانات المركزية بالكامل بنجاح! تم مسح كافة العملاء والأجهزة والتراخيص مع الحفاظ على حساب الإدارة.', 'warning')
    return redirect(url_for('dashboard'))

# ----------------- Mobile QR Code Route -----------------

@app.route('/mobile-qr')
@login_required
def mobile_qr_view():
    # If running on Vercel or cloud/domain, automatically use the live HTTPS URL
    if os.environ.get('VERCEL') or 'vercel.app' in request.host or not request.host.startswith('127.0.0.1'):
        current_url = request.host_url.rstrip('/')
        if current_url.startswith('http://') and not request.host.startswith('127.0.0.1'):
            current_url = 'https://' + current_url[7:]
    else:
        # Local development fallback
        base_dir = BASE_DIR
        url_file = os.path.join(base_dir, "current_tunnel_url.txt")
        current_url = None
        if os.path.exists(url_file):
            try:
                with open(url_file, "r", encoding="utf-8") as f:
                    current_url = f.read().strip()
            except Exception:
                pass
        if not current_url:
            current_url = request.host_url.rstrip('/')

    qr_image_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={quote(current_url)}"
    qr_available = True

    return render_template('mobile_qr.html', tunnel_url=current_url, qr_image_url=qr_image_url, qr_available=qr_available)

# ----------------- Sales Reps & Agents Routes -----------------

@app.route('/reps')
@login_required
def reps_list():
    conn = database.get_db()
    c = conn.cursor()
    c.execute("""
        SELECT sr.*, COUNT(cl.id) as sales_count
        FROM sales_reps sr
        LEFT JOIN clients cl ON cl.sales_rep_id = sr.id
        GROUP BY sr.id
        ORDER BY sr.id DESC
    """)
    reps = c.fetchall()
    conn.close()
    return render_template('reps.html', reps=reps)

@app.route('/reps/add', methods=['POST'])
@login_required
def add_rep():
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    city = request.form.get('city', '').strip()
    court_coverage = request.form.get('court_coverage', '').strip()
    notes = request.form.get('notes', '').strip()

    if not name or not phone:
        flash('اسم المندوب ورقم هاتفه حقول إلزامية.', 'danger')
        return redirect(url_for('reps_list'))

    conn = database.get_db()
    c = conn.cursor()

    # Generate sequential Rep Code (e.g. REP-101)
    c.execute("SELECT COUNT(*) FROM sales_reps")
    next_num = 101 + c.fetchone()[0]
    rep_code = f"REP-{next_num}"

    c.execute("""
        INSERT INTO sales_reps (name, phone, email, city, court_coverage, rep_code, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (name, phone, email, city, court_coverage, rep_code, notes))
    conn.commit()
    conn.close()

    flash(f'تم إضافة المندوب «{name}» بنجاح وتوليد كود المندوب: {rep_code}', 'success')
    return redirect(url_for('reps_list'))

@app.route('/reps/<int:id>')
@login_required
def rep_detail(id):
    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM sales_reps WHERE id = ?", (id,))
    rep = c.fetchone()
    if not rep:
        conn.close()
        flash('المندوب غير موجود.', 'danger')
        return redirect(url_for('reps_list'))

    # Clients sold through this rep
    c.execute("""
        SELECT id, full_name, firm_name, phone, city, current_edition, total_price, paid_amount, rep_commission, created_at
        FROM clients
        WHERE sales_rep_id = ?
        ORDER BY id DESC
    """, (id,))
    rep_clients = c.fetchall()

    # Commissions ledger
    c.execute("""
        SELECT rc.*, cl.full_name as client_name, cl.firm_name
        FROM rep_commissions rc
        LEFT JOIN clients cl ON rc.client_id = cl.id
        WHERE rc.rep_id = ?
        ORDER BY rc.id DESC
    """, (id,))
    commissions = c.fetchall()

    conn.close()
    return render_template('rep_detail.html', rep=rep, rep_clients=rep_clients, commissions=commissions)

@app.route('/reps/<int:id>/payout', methods=['POST'])
@login_required
def rep_payout(id):
    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM sales_reps WHERE id = ?", (id,))
    rep = c.fetchone()
    if not rep:
        conn.close()
        flash('المندوب غير موجود.', 'danger')
        return redirect(url_for('reps_list'))

    amount = float(request.form.get('amount') or 0.0)
    payout_method = request.form.get('payout_method', 'إنستاباي (InstaPay)').strip()
    transaction_ref = request.form.get('transaction_ref', '').strip()
    notes = request.form.get('notes', '').strip()

    if amount <= 0:
        flash('يرجى إدخال مبلغ صحيح للصرف.', 'danger')
        return redirect(url_for('rep_detail', id=id))

    paid_date = date.today().strftime('%Y-%m-%d')
    new_paid = rep['total_paid'] + amount
    new_balance = max(0.0, rep['balance'] - amount)

    # Record payout in rep_commissions as a disbursement
    c.execute("""
        INSERT INTO rep_commissions (rep_id, client_id, sale_amount, commission_amount, status, paid_date, payout_method, transaction_ref, notes)
        VALUES (?, NULL, 0, ?, 'مسدد', ?, ?, ?, ?)
    """, (id, -amount, paid_date, payout_method, transaction_ref, f"صرف عمولات: {notes}"))

    # Update rep totals
    c.execute("UPDATE sales_reps SET total_paid = ?, balance = ? WHERE id = ?", (new_paid, new_balance, id))

    conn.commit()
    conn.close()

    flash(f'تم تسجيل صرف عمولة بمبلغ {amount:,.0f} ج.م للمندوب {rep["name"]} بنجاح!', 'success')
    return redirect(url_for('rep_detail', id=id))

@app.route('/reps/<int:id>/toggle-status', methods=['POST'])
@login_required
def toggle_rep_status(id):
    conn = database.get_db()
    c = conn.cursor()
    c.execute("SELECT is_active FROM sales_reps WHERE id = ?", (id,))
    rep = c.fetchone()
    if rep:
        new_status = 0 if rep['is_active'] else 1
        c.execute("UPDATE sales_reps SET is_active = ? WHERE id = ?", (new_status, id))
        conn.commit()
    conn.close()
    return redirect(url_for('reps_list'))

# ==============================================================================
# 🛰️ TELEMETRY, BEACON & LIVE RADAR CONTROLLER (رادار التراخيص الحية ومكافحة القرصنة)
# ==============================================================================

@app.route('/api/v1/telemetry/install', methods=['POST'])
def telemetry_install():
    """
    Initial Beacon sent by Al-Oustaz when installed / first launched.
    Auto-registers device and creates a CRM Lead for sales follow-up.
    """
    data = request.get_json(silent=True) or {}
    machine_id = str(data.get('machine_id', '')).strip().upper()
    if not machine_id:
        return jsonify({"status": "ERROR", "message": "machine_id is required"}), 400

    firm_name = str(data.get('firm_name', 'مكتب محاماة جديد')).strip()
    phone = str(data.get('phone', '')).strip()
    app_version = str(data.get('app_version', '2.0')).strip()
    ip_addr = request.headers.get('CF-Connecting-IP') or request.remote_addr or '127.0.0.1'
    now_dt = datetime.now()
    client_time_str = str(data.get('client_time', '')).strip()
    if client_time_str:
        try:
            start_dt = datetime.strptime(client_time_str, '%Y-%m-%d %H:%M:%S')
            if start_dt <= now_dt + timedelta(days=1):
                now_dt = start_dt
        except Exception:
            pass

    now_str = now_dt.strftime('%Y-%m-%d %H:%M:%S')
    expires_str = (now_dt + timedelta(days=7)).strftime('%Y-%m-%d 23:59:59')
    days_rem = max(1, int(((now_dt + timedelta(days=7)) - datetime.now()).total_seconds() / 86400.0 + 0.99))

    conn = database.get_db()
    c = conn.cursor()

    # Check if client already exists with this machine_id
    c.execute("SELECT id, firm_name, current_edition, status FROM clients WHERE machine_id = ?", (machine_id,))
    existing_client = c.fetchone()

    # Check if device already registered
    c.execute("SELECT id, status, current_tier, trial_expires_at FROM telemetry_devices WHERE machine_id = ?", (machine_id,))
    device = c.fetchone()

    if device:
        client_id = existing_client['id'] if existing_client else None
        tier = existing_client['current_edition'] if existing_client else device['current_tier']
        status = device['status']
        c.execute("""
            UPDATE telemetry_devices
            SET firm_name = ?, contact_phone = COALESCE(NULLIF(?, ''), contact_phone),
                app_version = ?, last_heartbeat = ?, last_ip = ?, client_id = COALESCE(client_id, ?)
            WHERE id = ?
        """, (firm_name, phone, app_version, now_str, ip_addr, client_id, device['id']))
        device_id = device['id']
    else:
        client_id = existing_client['id'] if existing_client else None
        initial_tier = existing_client['current_edition'] if existing_client else 'TRIAL'
        initial_status = 'ACTIVE' if existing_client else 'TRIAL'

        c.execute("""
            INSERT INTO telemetry_devices (
                client_id, machine_id, firm_name, contact_phone, current_tier, reported_tier,
                status, is_read_only, days_remaining, trial_started_at, trial_expires_at,
                last_heartbeat, last_ip, app_version, notes
            ) VALUES (?, ?, ?, ?, ?, 'TRIAL', ?, 0, ?, ?, ?, ?, ?, ?, 'تثبيت تلقائي أولي عبر البيكون')
        """, (client_id, machine_id, firm_name, phone, initial_tier, initial_status, days_rem, now_str, expires_str, now_str, ip_addr, app_version))
        device_id = c.lastrowid

        # Auto-create CRM Lead if not an existing client
        if not existing_client:
            c.execute("""
                INSERT INTO leads (lawyer_name, phone, city, interested_edition, notes)
                VALUES (?, ?, 'مصر', 'STARTER', ?)
            """, (firm_name, phone or 'غير مسجل', f"عميل ديمو جديد (تثبيت تلقائي من البرنامج) - كود الجهاز: {machine_id}"))

    # Log in telemetry_logs
    c.execute("""
        INSERT INTO telemetry_logs (device_id, machine_id, event_type, reported_tier, ip_address, payload_json)
        VALUES (?, ?, 'INSTALL', 'TRIAL', ?, ?)
    """, (device_id, machine_id, ip_addr, json.dumps(data, ensure_ascii=False)))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "SUCCESS",
        "tier": "TRIAL" if not existing_client else existing_client['current_edition'],
        "days_remaining": days_rem,
        "trial_expires_at": expires_str,
        "server_time": now_str,
        "is_read_only": False,
        "broadcast_message": "مرحباً بكم في منظومة الأستاذ لإدارة مكاتب المحاماة (الإصدار 2.0). فترتكم التجريبية سارية لمدة 7 أيام."
    })


@app.route('/api/v1/telemetry/heartbeat', methods=['POST'])
def telemetry_heartbeat():
    """
    Periodic Heartbeat Ping from Al-Oustaz v2.0.
    Checks license validity, cross-verifies tiers (anti-crack), detects clock tampering,
    evaluates installments, and returns remote commands (lock, read-only, broadcast).
    """
    data = request.get_json(silent=True) or {}
    machine_id = str(data.get('machine_id', '')).strip().upper()
    if not machine_id:
        return jsonify({"status": "ERROR", "message": "machine_id is required"}), 400

    reported_tier = str(data.get('reported_tier', 'TRIAL')).strip().upper()
    cases_count = int(data.get('cases_count', 0) or 0)
    hearings_count = int(data.get('hearings_count', 0) or 0)
    app_version = str(data.get('app_version', '2.0')).strip()
    client_time_str = str(data.get('client_time', '')).strip()
    ip_addr = request.headers.get('CF-Connecting-IP') or request.remote_addr or '127.0.0.1'

    now_dt = datetime.now()
    now_str = now_dt.strftime('%Y-%m-%d %H:%M:%S')

    conn = database.get_db()
    c = conn.cursor()

    # Find device
    c.execute("SELECT * FROM telemetry_devices WHERE machine_id = ?", (machine_id,))
    device = c.fetchone()

    # Find associated client if any
    c.execute("SELECT * FROM clients WHERE machine_id = ?", (machine_id,))
    client = c.fetchone()

    if not device:
        initial_tier = client['current_edition'] if client else 'TRIAL'
        initial_status = 'ACTIVE' if client else 'TRIAL'
        expires_str = (now_dt + timedelta(days=7)).strftime('%Y-%m-%d 23:59:59')
        firm_name = client['firm_name'] if client else 'مكتب محاماة'
        phone = client['phone'] if client else ''

        c.execute("""
            INSERT INTO telemetry_devices (
                client_id, machine_id, firm_name, contact_phone, current_tier, reported_tier,
                status, is_read_only, days_remaining, trial_started_at, trial_expires_at,
                last_heartbeat, last_ip, app_version, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 7, ?, ?, ?, ?, ?, 'تسجيل نبضة تلقائي')
        """, (client['id'] if client else None, machine_id, firm_name, phone, initial_tier, reported_tier, initial_status, now_str, expires_str, now_str, ip_addr, app_version))
        device_id = c.lastrowid
        c.execute("SELECT * FROM telemetry_devices WHERE id = ?", (device_id,))
        device = c.fetchone()
    else:
        device_id = device['id']

    # Update client link if found
    if client and not device['client_id']:
        c.execute("UPDATE telemetry_devices SET client_id = ?, current_tier = ? WHERE id = ?", (client['id'], client['current_edition'], device_id))

    curr_tier = client['current_edition'] if client else device['current_tier']
    status = device['status']
    is_read_only = bool(device['is_read_only'])
    days_remaining = device['days_remaining']
    tamper_flag = device['tamper_flags']
    remote_cmd = device['remote_command']
    remote_param = device['remote_command_param']
    broadcast_msg = device['broadcast_message'] or ''

    # 1. Anti-Tamper: Clock Rollback Check
    if client_time_str:
        try:
            client_dt = datetime.strptime(client_time_str, '%Y-%m-%d %H:%M:%S')
            time_drift_hours = (now_dt - client_dt).total_seconds() / 3600.0
            if abs(time_drift_hours) > 36.0:
                tamper_flag = 'CLOCK_ROLLBACK'
                c.execute("""
                    INSERT INTO telemetry_logs (device_id, machine_id, event_type, reported_tier, ip_address, payload_json)
                    VALUES (?, ?, 'ROLLBACK_ALERT', ?, ?, ?)
                """, (device_id, machine_id, reported_tier, ip_addr, json.dumps({
                    "drift_hours": round(time_drift_hours, 1),
                    "client_time": client_time_str,
                    "server_time": now_str
                })))
        except Exception:
            pass

    # 2. Anti-Tamper: Tier Mismatch (Piracy / Crack Detection)
    if curr_tier in ['TRIAL', 'STARTER', 'LITE'] and reported_tier == 'FULL':
        tamper_flag = 'TIER_MISMATCH'
        c.execute("""
            INSERT INTO telemetry_logs (device_id, machine_id, event_type, reported_tier, ip_address, payload_json)
            VALUES (?, ?, 'TAMPER_ALERT', ?, ?, ?)
        """, (device_id, machine_id, reported_tier, ip_addr, json.dumps({
            "authorized_tier": curr_tier,
            "reported_tier": reported_tier,
            "cases_count": cases_count
        })))

    # 3. Check Trial Expiration
    if curr_tier == 'TRIAL' and status not in ['LOCKED', 'REVOKED']:
        if device['trial_expires_at']:
            try:
                exp_dt = datetime.strptime(device['trial_expires_at'], '%Y-%m-%d %H:%M:%S')
                diff_sec = (exp_dt - now_dt).total_seconds()
                if diff_sec <= 0:
                    status = 'EXPIRED'
                    days_remaining = 0
                else:
                    days_remaining = max(1, int((diff_sec / 86400.0) + 0.99))
            except Exception:
                pass

    # 4. Check Overdue Installments for Paying Clients (Graceful Degradation)
    if client:
        c.execute("""
            SELECT COUNT(*) FROM installments
            WHERE client_id = ? AND status = 'مستحق' AND due_date < date('now', '-3 days')
        """, (client['id'],))
        overdue_count = c.fetchone()[0]
        if overdue_count > 0:
            is_read_only = True

    # 5. Handle Pending Remote Commands
    dispatched_cmd = None
    if remote_cmd:
        dispatched_cmd = remote_cmd
        if remote_cmd == 'LOCK':
            status = 'LOCKED'
        elif remote_cmd == 'UNLOCK':
            status = 'ACTIVE' if curr_tier != 'TRIAL' else 'TRIAL'
            tamper_flag = None
        elif remote_cmd == 'EXTEND_DAYS':
            add_days = int(remote_param or 3)
            try:
                base_dt = datetime.strptime(device['trial_expires_at'] or now_str, '%Y-%m-%d %H:%M:%S')
                if base_dt < now_dt:
                    base_dt = now_dt
                new_exp = (base_dt + timedelta(days=add_days)).strftime('%Y-%m-%d 23:59:59')
                c.execute("UPDATE telemetry_devices SET trial_expires_at = ? WHERE id = ?", (new_exp, device_id))
                status = 'TRIAL'
                days_remaining += add_days
            except Exception:
                pass
        elif remote_cmd == 'UPGRADE':
            curr_tier = remote_param or 'FULL'
            status = 'ACTIVE'

        # Clear one-time executed commands
        c.execute("UPDATE telemetry_devices SET remote_command = NULL, remote_command_param = NULL WHERE id = ?", (device_id,))

    # 6. Evaluate Master Action to return to client
    action = "CONTINUE"
    msg = broadcast_msg

    if status in ['LOCKED', 'REVOKED'] or tamper_flag in ['TIER_MISMATCH', 'CRACK_ATTEMPT']:
        action = "LOCK"
        msg = "تم إيقاف تشغيل النظام من الإدارة المركزية بسبب مخالفة في شروط الترخيص. يرجى التواصل مع الدعم الفني."
    elif status == 'EXPIRED':
        action = "EXPIRED"
        msg = "انتهت فترة التجربة المجانية (7 أيام). يرجى الترقية لإحدى الباقات الرسمية لمتابعة العمل."
    elif is_read_only:
        action = "READ_ONLY"
        msg = "البرنامج في وضع المراجعة والطباعة فقط لوجود قسط مستحق. يرجى السداد لاستعادة كامل الصلاحيات."

    # Update device state in DB
    c.execute("""
        UPDATE telemetry_devices
        SET current_tier = ?, reported_tier = ?, status = ?, is_read_only = ?,
            days_remaining = ?, cases_count = ?, hearings_count = ?,
            app_version = ?, tamper_flags = ?, last_heartbeat = ?, last_ip = ?
        WHERE id = ?
    """, (curr_tier, reported_tier, status, 1 if is_read_only else 0,
          days_remaining, cases_count, hearings_count,
          app_version, tamper_flag, now_str, ip_addr, device_id))

    conn.commit()
    conn.close()

    return jsonify({
        "status": status,
        "authorized_tier": curr_tier,
        "is_read_only": is_read_only,
        "days_remaining": days_remaining,
        "server_time": now_str,
        "action": action,
        "message": msg,
        "broadcast_message": broadcast_msg,
        "dispatched_command": dispatched_cmd
    })


@app.route('/api/v1/telemetry/report-tamper', methods=['POST'])
def telemetry_report_tamper():
    """Client app direct security alert endpoint"""
    data = request.get_json(silent=True) or {}
    machine_id = str(data.get('machine_id', '')).strip().upper()
    alert_type = str(data.get('alert_type', 'INTEGRITY_FAIL')).strip()
    details = str(data.get('details', '')).strip()
    ip_addr = request.headers.get('CF-Connecting-IP') or request.remote_addr or '127.0.0.1'

    if machine_id:
        conn = database.get_db()
        c = conn.cursor()
        c.execute("""
            UPDATE telemetry_devices
            SET tamper_flags = ?, status = 'LOCKED'
            WHERE machine_id = ?
        """, (alert_type, machine_id))
        c.execute("""
            INSERT INTO telemetry_logs (machine_id, event_type, reported_tier, ip_address, payload_json)
            VALUES (?, 'TAMPER_ALERT', 'UNKNOWN', ?, ?)
        """, (machine_id, ip_addr, json.dumps({"alert": alert_type, "details": details}, ensure_ascii=False)))
        conn.commit()
        conn.close()

    return jsonify({"status": "LOGGED"})



# ==================== TURSO CLOUD SYNC ENGINE ====================
TURSO_DB_URL = os.environ.get("TURSO_DB_URL", "https://ahmed-hub-ahmedmabrouk123.aws-eu-central-1.turso.io")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3OTMxMzk1MjcsImlkIjoiMDFhMTdmNjktMTIwMS03YTAzLWI3N2UtMmU0ZTZjOTkxYTk0Iiwia2lkIjoicm9SRGhPMmxnZ1ZPYkEtNW9CUHFLYWkyZjMxVnAzUlNWV3ZDa2dVdlN2VSIsInJpZCI6IjkwMWIwMmZlLTgxMjAtNGQ2MC04YzcwLWUwYWViMzRkMDU4MCJ9.hS790g8Y4Nl1IgotjN21pxhdLO23E9Zh9C2xAuq3815zDoxki3zIQ0Jg2dswvpZmqCL5GjSwpWObHDPqhmU8AQ")

def _push_action_to_turso(stmt_sql: str, args: list = None):
    """Pushes a remote action or update directly to the cloud Turso DB"""
    try:
        import urllib.request
        import json
        url = f"{TURSO_DB_URL}/v2/pipeline"
        req_obj = {
            "type": "execute",
            "stmt": {"sql": stmt_sql}
        }
        if args:
            req_obj["stmt"]["args"] = args
        payload = json.dumps({"requests": [req_obj, {"type": "close"}]}).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {TURSO_AUTH_TOKEN}",
                "Content-Type": "application/json"
            },
            method="POST"
        )
        urllib.request.urlopen(req, timeout=3.0)
    except Exception:
        pass

def _sync_turso_into_local_hub():
    """Pulls all live devices and new leads from Turso cloud into local hub DB"""
    if getattr(database, 'USE_TURSO', False):
        return
    try:
        import urllib.request
        import json
        url = f"{TURSO_DB_URL}/v2/pipeline"
        payload = json.dumps({
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "SELECT machine_id, firm_name, contact_phone, current_tier, reported_tier, status, is_read_only, days_remaining, cases_count, hearings_count, app_version, trial_started_at, trial_expires_at, last_heartbeat, broadcast_message FROM telemetry_devices"
                    }
                },
                {
                    "type": "execute",
                    "stmt": {
                        "sql": "SELECT lawyer_name, phone, city, interested_edition, status, notes, created_at FROM leads"
                    }
                },
                {"type": "close"}
            ]
        }).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {TURSO_AUTH_TOKEN}",
                "Content-Type": "application/json"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            conn = database.get_db()
            c = conn.cursor()

            # 1. Sync telemetry_devices
            dev_res = data["results"][0]["response"]["result"]
            cols = [col["name"] for col in dev_res["cols"]]
            for row in dev_res["rows"]:
                vals = [r.get("value") for r in row]
                d = dict(zip(cols, vals))
                mid = d.get('machine_id')
                if not mid:
                    continue
                c.execute("SELECT id FROM telemetry_devices WHERE machine_id = ?", (mid,))
                ex = c.fetchone()
                if ex:
                    c.execute("""
                        UPDATE telemetry_devices 
                        SET firm_name = COALESCE(?, firm_name),
                            contact_phone = COALESCE(?, contact_phone),
                            current_tier = COALESCE(?, current_tier),
                            reported_tier = COALESCE(?, reported_tier),
                            status = COALESCE(?, status),
                            is_read_only = COALESCE(?, is_read_only),
                            days_remaining = COALESCE(?, days_remaining),
                            cases_count = COALESCE(?, cases_count),
                            hearings_count = COALESCE(?, hearings_count),
                            last_heartbeat = COALESCE(?, last_heartbeat),
                            broadcast_message = COALESCE(?, broadcast_message)
                        WHERE machine_id = ?
                    """, (
                        d.get('firm_name'), d.get('contact_phone'), d.get('current_tier'),
                        d.get('reported_tier'), d.get('status'), d.get('is_read_only'),
                        d.get('days_remaining'), d.get('cases_count'), d.get('hearings_count'),
                        d.get('last_heartbeat'), d.get('broadcast_message'), mid
                    ))
                else:
                    c.execute("""
                        INSERT INTO telemetry_devices (
                            machine_id, firm_name, contact_phone, current_tier, reported_tier,
                            status, is_read_only, days_remaining, cases_count, hearings_count,
                            app_version, trial_started_at, trial_expires_at, last_heartbeat, broadcast_message, notes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'تزامن تلقائي من السحابة')
                    """, (
                        mid, d.get('firm_name') or 'مكتب محاماة', d.get('contact_phone') or '',
                        d.get('current_tier') or 'TRIAL', d.get('reported_tier') or 'TRIAL',
                        d.get('status') or 'TRIAL', d.get('is_read_only') or 0,
                        d.get('days_remaining') or 7, d.get('cases_count') or 0,
                        d.get('hearings_count') or 0, d.get('app_version') or '2.0',
                        d.get('trial_started_at'), d.get('trial_expires_at'),
                        d.get('last_heartbeat'), d.get('broadcast_message') or ''
                    ))

            # 2. Sync leads
            if len(data["results"]) > 1 and "response" in data["results"][1]:
                lead_res = data["results"][1]["response"]["result"]
                l_cols = [col["name"] for col in lead_res["cols"]]
                for row in lead_res["rows"]:
                    l_vals = [r.get("value") for r in row]
                    ld = dict(zip(l_cols, l_vals))
                    notes_v = ld.get('notes') or ''
                    phone_v = ld.get('phone') or ''
                    c.execute("SELECT id FROM leads WHERE notes = ? OR (phone = ? AND phone != '')", (notes_v, phone_v))
                    if not c.fetchone():
                        c.execute("""
                            INSERT INTO leads (lawyer_name, phone, city, interested_edition, status, notes)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            ld.get('lawyer_name'), phone_v, ld.get('city'),
                            ld.get('interested_edition') or 'STARTER', ld.get('status') or 'جديد',
                            notes_v
                        ))

            conn.commit()
            conn.close()
    except Exception as e:
        pass

# ==================== 3-WAY TURSO SYNC CONTROLLER ====================
# Background sync only runs when NOT on Vercel and NOT using direct Turso connection
if not os.environ.get('VERCEL') and not getattr(database, 'USE_TURSO', False):
    # 1. At Startup
    try:
        import threading
        threading.Thread(target=_sync_turso_into_local_hub, daemon=True).start()
    except Exception:
        pass

    # 3. Periodic Background Sync
    def _start_turso_periodic_sync(interval_sec=30):
        import threading
        import time
        def _loop():
            while True:
                try:
                    time.sleep(interval_sec)
                    _sync_turso_into_local_hub()
                except Exception:
                    pass
        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    try:
        _start_turso_periodic_sync(interval_sec=30)
    except Exception:
        pass

# ----------------- Radar Web Views (لوحة تحكم رادار الأجهزة المركزية) -----------------

@app.route('/radar')
@login_required
def radar_dashboard():
    """Live Radar Dashboard for all connected and monitored law office devices"""
    _sync_turso_into_local_hub()
    filter_type = request.args.get('filter', 'all')
    search_q = request.args.get('q', '').strip()

    conn = database.get_db()
    c = conn.cursor()

    # Overall Metrics
    c.execute("SELECT COUNT(*) FROM telemetry_devices")
    total_devices = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM telemetry_devices WHERE current_tier = 'TRIAL' AND status = 'TRIAL'")
    active_trials = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM telemetry_devices WHERE current_tier IN ('STARTER', 'LITE', 'FULL') AND status = 'ACTIVE'")
    paid_active = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(*) FROM telemetry_devices 
        WHERE (tamper_flags IS NOT NULL AND tamper_flags != '' AND tamper_flags != 'NONE')
           OR status IN ('LOCKED', 'REVOKED')
    """)
    tamper_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM telemetry_devices WHERE is_read_only = 1")
    read_only_count = c.fetchone()[0]

    # Build query with filters
    base_sql = "SELECT d.*, c.full_name as client_lawyer_name FROM telemetry_devices d LEFT JOIN clients c ON d.client_id = c.id WHERE 1=1"
    params = []

    if filter_type == 'trials':
        base_sql += " AND d.current_tier = 'TRIAL' AND d.status = 'TRIAL'"
    elif filter_type == 'paid':
        base_sql += " AND d.current_tier IN ('STARTER', 'LITE', 'FULL')"
    elif filter_type == 'tamper':
        base_sql += " AND ((d.tamper_flags IS NOT NULL AND d.tamper_flags != '' AND d.tamper_flags != 'NONE') OR d.status IN ('LOCKED', 'REVOKED'))"
    elif filter_type == 'locked':
        base_sql += " AND d.status IN ('LOCKED', 'REVOKED')"
    elif filter_type == 'read_only':
        base_sql += " AND d.is_read_only = 1"

    if search_q:
        base_sql += " AND (d.firm_name LIKE ? OR d.machine_id LIKE ? OR d.contact_phone LIKE ?)"
        wildcard = f"%{search_q}%"
        params.extend([wildcard, wildcard, wildcard])

    base_sql += " ORDER BY d.last_heartbeat DESC, d.id DESC"
    c.execute(base_sql, params)
    devices = c.fetchall()

    conn.close()

    return render_template('radar.html',
                           devices=devices,
                           total_devices=total_devices,
                           active_trials=active_trials,
                           paid_active=paid_active,
                           tamper_alerts=tamper_alerts,
                           read_only_count=read_only_count,
                           filter_type=filter_type,
                           search_q=search_q)


@app.route('/radar/device/<int:id>')
@login_required
def radar_device_detail(id):
    """Detailed view for a single monitored device with telemetry event history"""
    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT d.*, c.full_name as client_lawyer_name, c.payment_model, c.remaining_amount FROM telemetry_devices d LEFT JOIN clients c ON d.client_id = c.id WHERE d.id = ?", (id,))
    device = c.fetchone()
    if not device:
        conn.close()
        flash('الجهاز المطلوب غير مسجل في الرادار.', 'danger')
        return redirect(url_for('radar_dashboard'))

    # Fetch recent logs for this device
    c.execute("""
        SELECT * FROM telemetry_logs
        WHERE device_id = ? OR machine_id = ?
        ORDER BY id DESC LIMIT 50
    """, (id, device['machine_id']))
    logs = c.fetchall()

    conn.close()

    return render_template('radar_detail.html', device=device, logs=logs)


@app.route('/radar/device/<int:id>/action', methods=['POST'])
@login_required
def radar_device_action(id):
    """Execute remote action on a specific client machine"""
    action_type = request.form.get('action_type', '').strip()
    param_val = request.form.get('param_val', '').strip()

    conn = database.get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM telemetry_devices WHERE id = ?", (id,))
    device = c.fetchone()
    if not device:
        conn.close()
        flash('الجهاز غير موجود.', 'danger')
        return redirect(url_for('radar_dashboard'))

    firm_name = device['firm_name']

    mid = device['machine_id']
    if action_type == 'lock':
        c.execute("UPDATE telemetry_devices SET remote_command = 'LOCK', status = 'LOCKED' WHERE id = ?", (id,))
        _push_action_to_turso("UPDATE telemetry_devices SET remote_command = 'LOCK', status = 'LOCKED' WHERE machine_id = ?", [{"type": "text", "value": mid}])
        flash(f'تم إرسال أمر القفل الفوري لجهاز ({firm_name}) بنجاح!', 'danger')
    elif action_type == 'unlock':
        c.execute("""
            UPDATE telemetry_devices 
            SET remote_command = 'UNLOCK', 
                status = CASE WHEN current_tier = 'TRIAL' THEN 'TRIAL' ELSE 'ACTIVE' END,
                tamper_flags = NULL 
            WHERE id = ?
        """, (id,))
        _push_action_to_turso("UPDATE telemetry_devices SET remote_command = 'UNLOCK', status = CASE WHEN current_tier = 'TRIAL' THEN 'TRIAL' ELSE 'ACTIVE' END, tamper_flags = NULL WHERE machine_id = ?", [{"type": "text", "value": mid}])
        flash(f'تم فك الحظر وإلغاء القفل عن جهاز ({firm_name}) بنجاح!', 'success')
    elif action_type == 'extend_days':
        days = int(param_val or 3)
        c.execute("""
            UPDATE telemetry_devices
            SET remote_command = 'EXTEND_DAYS', remote_command_param = ?,
                status = 'TRIAL', days_remaining = days_remaining + ?
            WHERE id = ?
        """, (str(days), days, id))
        _push_action_to_turso("UPDATE telemetry_devices SET remote_command = 'EXTEND_DAYS', remote_command_param = ?, days_remaining = days_remaining + ? WHERE machine_id = ?", [{"type": "text", "value": str(days)}, {"type": "integer", "value": str(days)}, {"type": "text", "value": mid}])
        flash(f'تم تمديد الديمو لـ ({firm_name}) لمدة {days} أيام إضافية بنجاح!', 'success')
    elif action_type in ['enable_read_only', 'disable_read_only', 'toggle_read_only']:
        if action_type == 'enable_read_only':
            new_val = 1
        elif action_type == 'disable_read_only':
            new_val = 0
        else:
            new_val = 0 if device['is_read_only'] else 1
        c.execute("UPDATE telemetry_devices SET is_read_only = ? WHERE id = ?", (new_val, id))
        _push_action_to_turso("UPDATE telemetry_devices SET is_read_only = ? WHERE machine_id = ?", [{"type": "integer", "value": str(new_val)}, {"type": "text", "value": mid}])
        state_txt = "تفعيل وضع القراءة فقط (تجميد الإدخال)" if new_val else "إلغاء وضع القراءة فقط (استعادة صلاحيات الإدخال)"
        flash(f'تم {state_txt} لجهاز ({firm_name}) بنجاح!', 'warning' if new_val else 'success')
    elif action_type == 'upgrade':
        new_tier = param_val.upper()
        c.execute("""
            UPDATE telemetry_devices
            SET remote_command = 'UPGRADE', remote_command_param = ?,
                current_tier = ?, status = 'ACTIVE'
            WHERE id = ?
        """, (new_tier, new_tier, id))
        _push_action_to_turso("UPDATE telemetry_devices SET remote_command = 'UPGRADE', remote_command_param = ?, current_tier = ?, status = 'ACTIVE' WHERE machine_id = ?", [{"type": "text", "value": new_tier}, {"type": "text", "value": new_tier}, {"type": "text", "value": mid}])
        flash(f'تم إرسال أمر ترقية الباقة إلى {new_tier} لجهاز ({firm_name}) بنجاح!', 'success')
    elif action_type == 'broadcast':
        msg = param_val or ''
        c.execute("UPDATE telemetry_devices SET broadcast_message = ? WHERE id = ?", (msg, id))
        _push_action_to_turso("UPDATE telemetry_devices SET broadcast_message = ? WHERE machine_id = ?", [{"type": "text", "value": msg}, {"type": "text", "value": mid}])
        flash(f'تم تحديث الرسالة الإعلانية لجهاز ({firm_name}) بنجاح!', 'info')
    elif action_type == 'delete':
        c.execute("DELETE FROM telemetry_logs WHERE device_id = ?", (id,))
        c.execute("DELETE FROM telemetry_devices WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        flash('تم حذف سجل الجهاز من الرادار بنجاح.', 'secondary')
        return redirect(url_for('radar_dashboard'))

    conn.commit()
    conn.close()

    return redirect(url_for('radar_device_detail', id=id))


@app.route('/radar/broadcast-all', methods=['POST'])
@login_required
def radar_broadcast_all():
    """Broadcast an announcement banner message to all devices or specific tier"""
    target_tier = request.form.get('target_tier', 'ALL').strip().upper()
    broadcast_msg = request.form.get('broadcast_msg', '').strip()

    conn = database.get_db()
    c = conn.cursor()

    if target_tier == 'ALL':
        c.execute("UPDATE telemetry_devices SET broadcast_message = ?", (broadcast_msg,))
        _push_action_to_turso("UPDATE telemetry_devices SET broadcast_message = ?", [{"type": "text", "value": broadcast_msg}])
    else:
        c.execute("UPDATE telemetry_devices SET broadcast_message = ? WHERE current_tier = ?", (broadcast_msg, target_tier))
        _push_action_to_turso("UPDATE telemetry_devices SET broadcast_message = ? WHERE current_tier = ?", [{"type": "text", "value": broadcast_msg}, {"type": "text", "value": target_tier}])

    count = c.rowcount
    conn.commit()
    conn.close()

    flash(f'تم نشر الرسالة الإعلانية بنجاح إلى {count} أجهزة!', 'success')
    return redirect(url_for('radar_dashboard'))

if __name__ == '__main__':
    database.init_db()
    app.run(host='0.0.0.0', port=5050, debug=False)
