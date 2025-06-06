"""
Database Manager for CybrScan
Handles all database operations and schema management
"""

import sqlite3
import os
import hashlib
import secrets
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

DATABASE_PATH = 'database/cybrscan.db'

def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with all required tables"""
    if not os.path.exists('database'):
        os.makedirs('database')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'client',
                subscription_level TEXT DEFAULT 'basic',
                full_name TEXT,
                company TEXT,
                phone TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT,
                is_active INTEGER DEFAULT 1,
                email_verified INTEGER DEFAULT 0,
                subscription_expires TEXT,
                monthly_scans_used INTEGER DEFAULT 0,
                monthly_scans_reset TEXT,
                payment_method_id TEXT
            )
        ''')
        
        # Scanners table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scanners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                api_key TEXT UNIQUE NOT NULL,
                
                -- Customization settings
                logo_url TEXT,
                favicon_url TEXT,
                primary_color TEXT DEFAULT '#007bff',
                secondary_color TEXT DEFAULT '#6c757d',
                accent_color TEXT DEFAULT '#28a745',
                background_color TEXT DEFAULT '#ffffff',
                text_color TEXT DEFAULT '#212529',
                
                title TEXT DEFAULT 'Security Scanner',
                subtitle TEXT DEFAULT 'Powered by CybrScan',
                footer_text TEXT DEFAULT 'Professional Security Assessment',
                
                -- Advanced customization
                css_overrides TEXT,
                custom_domain TEXT,
                auto_color_detection INTEGER DEFAULT 1,
                
                -- Scanner settings
                scan_types TEXT DEFAULT '["basic", "ssl", "ports"]',
                max_targets INTEGER DEFAULT 1,
                timeout_seconds INTEGER DEFAULT 30,
                
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanner_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                target_url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                
                -- Results
                results TEXT,
                vulnerabilities_found INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                
                -- Metadata
                ip_address TEXT,
                user_agent TEXT,
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                duration_seconds INTEGER,
                
                -- Report generation
                report_generated INTEGER DEFAULT 0,
                report_path TEXT,
                
                FOREIGN KEY (scanner_id) REFERENCES scanners (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Scanner customizations table (for storing detected colors)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scanner_customizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanner_id INTEGER NOT NULL,
                target_domain TEXT NOT NULL,
                
                -- Auto-detected colors
                detected_primary TEXT,
                detected_secondary TEXT,
                detected_accent TEXT,
                detected_background TEXT,
                detected_text TEXT,
                
                -- Metadata
                favicon_detected TEXT,
                title_detected TEXT,
                detection_timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                detection_confidence REAL DEFAULT 0.0,
                
                FOREIGN KEY (scanner_id) REFERENCES scanners (id) ON DELETE CASCADE,
                UNIQUE(scanner_id, target_domain)
            )
        ''')
        
        # Subscription history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscription_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subscription_level TEXT NOT NULL,
                price REAL NOT NULL,
                billing_cycle TEXT DEFAULT 'monthly',
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT,
                payment_id TEXT,
                status TEXT DEFAULT 'active',
                
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Admin settings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER,
                
                FOREIGN KEY (updated_by) REFERENCES users (id)
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scanners_user ON scanners(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scanners_api_key ON scanners(api_key)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_scanner ON scans(scanner_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)')
        
        # Create default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            salt = secrets.token_hex(32)
            password = 'admin123'  # Default password - should be changed
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, full_name, subscription_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('admin', 'admin@cybrscan.com', password_hash, salt, 'admin', 'System Administrator', 'enterprise'))
            
            logger.info('Default admin user created - username: admin, password: admin123')
        
        # Insert default admin settings
        default_settings = [
            ('site_name', 'CybrScan'),
            ('site_description', 'Professional Security Scanning Platform'),
            ('max_free_scans', '10'),
            ('scanner_timeout', '30'),
            ('enable_registration', 'true'),
            ('maintenance_mode', 'false')
        ]
        
        for key, value in default_settings:
            cursor.execute('''
                INSERT OR IGNORE INTO admin_settings (key, value)
                VALUES (?, ?)
            ''', (key, value))
        
        conn.commit()
        logger.info('Database initialized successfully')
        
    except Exception as e:
        conn.rollback()
        logger.error(f'Database initialization failed: {e}')
        raise
    finally:
        conn.close()

def get_user_by_email(email):
    """Get user by email address"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', (email,))
        user = cursor.fetchone()
        return dict(user) if user else None
    finally:
        conn.close()

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM users WHERE id = ? AND is_active = 1', (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None
    finally:
        conn.close()

def verify_password(password, password_hash, salt):
    """Verify password against hash"""
    return hashlib.sha256((password + salt).encode()).hexdigest() == password_hash

def create_user(username, email, password, full_name=None, company=None, subscription_level='basic'):
    """Create new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        salt = secrets.token_hex(32)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, full_name, company, subscription_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, salt, full_name, company, subscription_level))
        
        user_id = cursor.lastrowid
        conn.commit()
        return user_id
        
    finally:
        conn.close()

def get_scanner_by_api_key(api_key):
    """Get scanner by API key"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT s.*, u.username, u.subscription_level 
            FROM scanners s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.api_key = ? AND s.is_active = 1
        ''', (api_key,))
        scanner = cursor.fetchone()
        return dict(scanner) if scanner else None
    finally:
        conn.close()

def save_scan_result(scanner_id, user_id, target_url, scan_type, results, ip_address=None, user_agent=None):
    """Save scan results to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        vulnerabilities = len(results.get('vulnerabilities', [])) if isinstance(results, dict) else 0
        risk_score = results.get('risk_score', 0) if isinstance(results, dict) else 0
        
        cursor.execute('''
            INSERT INTO scans (
                scanner_id, user_id, target_url, scan_type, status, results,
                vulnerabilities_found, risk_score, ip_address, user_agent, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scanner_id, user_id, target_url, scan_type, 'completed',
            json.dumps(results) if isinstance(results, dict) else str(results),
            vulnerabilities, risk_score, ip_address, user_agent, datetime.now().isoformat()
        ))
        
        scan_id = cursor.lastrowid
        conn.commit()
        return scan_id
        
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")