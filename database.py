# -*- coding: utf-8 -*-
import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get('VENDOR_HUB_DB_PATH', os.path.join(BASE_DIR, "vendor_hub.db"))
TURSO_DB_URL = os.environ.get('TURSO_DB_URL', "https://ahmed-hub-ahmedmabrouk123.aws-eu-central-1.turso.io")
TURSO_AUTH_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3OTMxMzk1MjcsImlkIjoiMDFhMTdmNjktMTIwMS03YTAzLWI3N2UtMmU0ZTZjOTkxYTk0Iiwia2lkIjoicm9SRGhPMmxnZ1ZPYkEtNW9CUHFLYWkyZjMxVnAzUlNWV3ZDa2dVdlN2VSIsInJpZCI6IjkwMWIwMmZlLTgxMjAtNGQ2MC04YzcwLWUwYWViMzRkMDU4MCJ9.hS790g8Y4Nl1IgotjN21pxhdLO23E9Zh9C2xAuq3815zDoxki3zIQ0Jg2dswvpZmqCL5GjSwpWObHDPqhmU8AQ")

USE_TURSO = os.environ.get('USE_TURSO', '1') == '1' or bool(os.environ.get('VERCEL'))

class TursoRow:
    def __init__(self, cols, values):
        self._cols = list(cols or [])
        self._values = list(values or [])
        self._col_map = {str(c).lower(): v for c, v in zip(self._cols, self._values)}
        self._orig_map = {str(c): v for c, v in zip(self._cols, self._values)}

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        s_key = str(key)
        if s_key in self._orig_map:
            return self._orig_map[s_key]
        return self._col_map.get(s_key.lower())

    def __getattr__(self, name):
        if name in self.__dict__:
            return self.__dict__[name]
        s_name = str(name)
        if s_name in self._orig_map:
            return self._orig_map[s_name]
        if s_name.lower() in self._col_map:
            return self._col_map[s_name.lower()]
        raise AttributeError(f"'TursoRow' object has no attribute '{name}'")

    def get(self, key, default=None):
        try:
            val = self[key]
            return val if val is not None else default
        except (KeyError, IndexError, AttributeError):
            return default

    def keys(self):
        return self._cols

    def values(self):
        return self._values

    def items(self):
        return list(zip(self._cols, self._values))

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return f"<TursoRow {dict(zip(self._cols, self._values))}>"


class TursoCursor:
    def __init__(self, client):
        self.client = client
        self.description = None
        self._rows = []
        self._idx = 0
        self.rowcount = 0
        self.lastrowid = None

    def execute(self, sql, params=None):
        clean_sql = sql.strip()
        p = list(params) if params is not None else []
        res = self.client.execute(clean_sql, p)
        self.description = [(c, None, None, None, None, None, None) for c in (res.columns or [])]
        self._rows = [TursoRow(res.columns, r) for r in (res.rows or [])]
        self._idx = 0
        self.rowcount = res.rows_affected or len(self._rows)
        self.lastrowid = res.last_insert_rowid
        return self

    def fetchone(self):
        if self._idx < len(self._rows):
            r = self._rows[self._idx]
            self._idx += 1
            return r
        return None

    def fetchall(self):
        r = self._rows[self._idx:]
        self._idx = len(self._rows)
        return r


class TursoConnection:
    def __init__(self, url, auth_token):
        import libsql_client
        self.client = libsql_client.create_client_sync(url=url, auth_token=auth_token)
        self.row_factory = None

    def cursor(self):
        return TursoCursor(self.client)

    def execute(self, sql, params=None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass


def get_db():
    if USE_TURSO and TURSO_DB_URL and TURSO_AUTH_TOKEN:
        try:
            return TursoConnection(TURSO_DB_URL, TURSO_AUTH_TOKEN)
        except Exception as e:
            pass

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # 1. Admin Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Clients Table (Law Firms)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            firm_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            city TEXT,
            machine_id TEXT NOT NULL,
            current_edition TEXT NOT NULL DEFAULT 'FULL',
            payment_model TEXT NOT NULL DEFAULT 'كاش كامل',
            total_price REAL DEFAULT 0.0,
            paid_amount REAL DEFAULT 0.0,
            remaining_amount REAL DEFAULT 0.0,
            next_payment_date TEXT,
            status TEXT DEFAULT 'نشط',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Issued Licenses History
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            license_key TEXT NOT NULL,
            license_type TEXT NOT NULL,
            duration_type TEXT NOT NULL DEFAULT 'LIFETIME',
            expires_at TEXT,
            machine_id TEXT NOT NULL,
            max_cases INTEGER,
            is_active INTEGER DEFAULT 1,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE SET NULL
        )
    """)

    # 4. Financial Payments (Receipts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payment_date TEXT NOT NULL,
            payment_method TEXT NOT NULL DEFAULT 'إنستاباي (InstaPay)',
            transaction_ref TEXT,
            receipt_number TEXT UNIQUE,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        )
    """)

    # 5. Device Migrations & Hardware Changes Log
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            old_machine_id TEXT NOT NULL,
            new_machine_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            migrated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        )
    """)

    # 6. Sales Leads & Follow-ups Pipeline
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lawyer_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            city TEXT,
            interested_edition TEXT DEFAULT 'STARTER',
            expected_contact_date TEXT,
            status TEXT DEFAULT 'قيد المتابعة',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 7. Installments & Scheduled Payments Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS installments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            installment_no INTEGER NOT NULL,
            title TEXT NOT NULL,
            due_date TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'مستحق', -- 'مستحق', 'مسدد'
            paid_date TEXT,
            payment_method TEXT,
            receipt_number TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        )
    """)

    # 8. Schema Upgrades for Referrals & Complimentary Gifts & Sales Reps
    cursor.execute("PRAGMA table_info(clients)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    new_cols = [
        ("referred_by_id", "INTEGER REFERENCES clients(id)"),
        ("referral_discount", "REAL DEFAULT 0.0"),
        ("referral_reward", "REAL DEFAULT 0.0"),
        ("referral_reward_status", "TEXT DEFAULT 'معلق'"),
        ("is_complimentary", "INTEGER DEFAULT 0"),
        ("complimentary_nominal_value", "REAL DEFAULT 0.0"),
        ("complimentary_reason", "TEXT"),
        ("sales_rep_id", "INTEGER REFERENCES sales_reps(id)"),
        ("rep_commission", "REAL DEFAULT 0.0")
    ]
    for col_name, col_def in new_cols:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE clients ADD COLUMN {col_name} {col_def}")

    # 9. Sales Reps Table (مناديب وسفراء المبيعات الميدانيين)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sales_reps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            city TEXT,
            court_coverage TEXT,
            rep_code TEXT UNIQUE,
            total_earned REAL DEFAULT 0.0,
            total_paid REAL DEFAULT 0.0,
            balance REAL DEFAULT 0.0,
            is_active INTEGER DEFAULT 1,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 10. Rep Commissions & Payouts Ledger
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rep_commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rep_id INTEGER NOT NULL,
            client_id INTEGER,
            sale_amount REAL NOT NULL,
            commission_amount REAL NOT NULL,
            status TEXT DEFAULT 'مستحق', -- 'مستحق', 'مسدد'
            paid_date TEXT,
            payout_method TEXT,
            transaction_ref TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (rep_id) REFERENCES sales_reps (id) ON DELETE CASCADE,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE SET NULL
        )
    """)

    # 11. Telemetry & Remote Licensing Radar (رادار الأجهزة والبيكون الصامت)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            machine_id TEXT UNIQUE NOT NULL,
            firm_name TEXT NOT NULL,
            contact_phone TEXT,
            current_tier TEXT NOT NULL DEFAULT 'TRIAL', -- 'TRIAL', 'STARTER', 'LITE', 'FULL'
            reported_tier TEXT DEFAULT 'TRIAL',
            status TEXT NOT NULL DEFAULT 'TRIAL', -- 'TRIAL', 'ACTIVE', 'EXPIRED', 'LOCKED', 'REVOKED'
            is_read_only INTEGER DEFAULT 0,
            days_remaining INTEGER DEFAULT 7,
            trial_started_at TEXT,
            trial_expires_at TEXT,
            last_heartbeat TEXT,
            last_ip TEXT,
            cases_count INTEGER DEFAULT 0,
            hearings_count INTEGER DEFAULT 0,
            app_version TEXT DEFAULT '2.0',
            tamper_flags TEXT,
            remote_command TEXT,
            remote_command_param TEXT,
            broadcast_message TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE SET NULL
        )
    """)

    # 12. Telemetry Audit Logs (سجل النبضات وإشارات التلاعب)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            machine_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            reported_tier TEXT,
            ip_address TEXT,
            payload_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES telemetry_devices (id) ON DELETE CASCADE
        )
    """)

    # Create default admin user if none exists:
    cursor.execute("SELECT id FROM admin_users WHERE username = 'ahmed'")
    if not cursor.fetchone():
        pwd_hash = generate_password_hash("admin123")
        cursor.execute("""
            INSERT INTO admin_users (username, password_hash, full_name, phone, email)
            VALUES (?, ?, ?, ?, ?)
        """, ('ahmed', pwd_hash, 'Ahmed Mabrouk', '+201550597688', 'Ahmed.Mabrouk20011@gmail.com'))

    conn.commit()
    conn.close()
    print("SUCCESS: Vendor Hub Database initialized successfully!")

def create_backup(target_dir=None, max_keep=30) -> str:
    """
    Creates an atomic, consistent backup of vendor_hub.db using SQLite's native backup API.
    Flushes WAL frames and produces a standalone .db file.
    Returns the absolute path of the created backup file.
    """
    from datetime import datetime
    if target_dir is None:
        target_dir = os.path.join(BASE_DIR, "backups")
    os.makedirs(target_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"vendor_hub_backup_{timestamp}.db"
    backup_path = os.path.join(target_dir, backup_filename)
    
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(backup_path)
    with dst:
        src.backup(dst, pages=100)
    dst.close()
    src.close()
    
    # Prune old backups if count > max_keep
    try:
        backups = sorted([os.path.join(target_dir, f) for f in os.listdir(target_dir) if f.startswith("vendor_hub_backup_") and f.endswith(".db")])
        if len(backups) > max_keep:
            for old_b in backups[:-max_keep]:
                os.remove(old_b)
    except Exception:
        pass
        
    return backup_path

if __name__ == '__main__':
    init_db()
