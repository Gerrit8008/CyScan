from pathlib import Path
import sqlite3
import logging
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any, List

class DatabaseManager:
    """
    Enhanced Database Manager for CybrScan
    Handles multi-tenant client databases and admin database operations
    """
    
    def __init__(self, base_path='./databases'):
        self.base_path = Path(base_path)
        self.admin_db_path = self.base_path / 'admin.db'
        self.client_databases_path = self.base_path / 'clients'
        
        # Create directories
        self.base_path.mkdir(exist_ok=True)
        self.client_databases_path.mkdir(exist_ok=True)
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize databases
        self._init_admin_database()

    def _init_admin_database(self):
        """Initialize the main admin database with enhanced schema"""
        try:
            conn = sqlite3.connect(self.admin_db_path)
            cursor = conn.cursor()
            
            # Read and execute admin schema
            schema_path = Path(__file__).parent.parent / 'admin_schema.sql'
            if schema_path.exists():
                with open(schema_path, 'r') as f:
                    schema_sql = f.read()
                    cursor.executescript(schema_sql)
            else:
                # Fallback to inline schema
                self._create_admin_tables(cursor)
            
            conn.commit()
            self.logger.info("Admin database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing admin database: {e}")
            raise
        finally:
            conn.close()

    def _create_admin_tables(self, cursor):
        """Create admin tables if schema file not found"""
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'client',
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            active INTEGER DEFAULT 1
        )''')
        
        # Clients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            business_name TEXT NOT NULL,
            business_domain TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            contact_phone TEXT,
            subscription_level TEXT DEFAULT 'basic',
            subscription_status TEXT DEFAULT 'active',
            subscription_start TEXT,
            subscription_end TEXT,
            database_name TEXT UNIQUE,
            created_at TEXT,
            created_by INTEGER,
            active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        # Deployed scanners table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS deployed_scanners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            scanner_name TEXT NOT NULL,
            subdomain TEXT UNIQUE,
            api_key TEXT UNIQUE,
            status TEXT DEFAULT 'active',
            created_at TEXT,
            last_active TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        )''')

    def create_client_database(self, client_id: int, business_name: str) -> str:
        """Create a new isolated database for a client"""
        try:
            # Create sanitized database name
            sanitized_name = business_name.lower().replace(' ', '_').replace('-', '_')
            sanitized_name = ''.join(c for c in sanitized_name if c.isalnum() or c == '_')
            db_name = f"client_{client_id}_{sanitized_name}.db"
            db_path = self.client_databases_path / db_name
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Read and execute client schema
            schema_path = Path(__file__).parent.parent / 'client_schema.sql'
            if schema_path.exists():
                with open(schema_path, 'r') as f:
                    schema_sql = f.read()
                    cursor.executescript(schema_sql)
            else:
                # Fallback to inline schema
                self._create_client_tables(cursor)
            
            conn.commit()
            conn.close()
            
            # Update main database with the client's database name
            admin_conn = sqlite3.connect(self.admin_db_path)
            cursor = admin_conn.cursor()
            cursor.execute("""
                UPDATE clients 
                SET database_name = ? 
                WHERE id = ?
            """, (db_name, client_id))
            admin_conn.commit()
            admin_conn.close()
            
            self.logger.info(f"Created client database: {db_name}")
            return db_name
            
        except Exception as e:
            self.logger.error(f"Error creating client database: {e}")
            raise

    def _create_client_tables(self, cursor):
        """Create client tables if schema file not found"""
        # Scans table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanner_id TEXT NOT NULL,
            scan_timestamp TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            results TEXT,
            report_path TEXT,
            created_at TEXT,
            vulnerability_count INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0
        )''')
        
        # Leads table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanner_id TEXT NOT NULL,
            name TEXT,
            email TEXT NOT NULL,
            company TEXT,
            phone TEXT,
            source TEXT,
            status TEXT DEFAULT 'new',
            created_at TEXT,
            notes TEXT
        )''')
        
        # Scan configurations table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanner_id TEXT NOT NULL,
            name TEXT NOT NULL,
            configuration TEXT NOT NULL,
            is_default BOOLEAN DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )''')

    def get_client_connection(self, client_id: int) -> sqlite3.Connection:
        """Get a connection to a client's database"""
        try:
            admin_conn = sqlite3.connect(self.admin_db_path)
            cursor = admin_conn.cursor()
            cursor.execute("SELECT database_name FROM clients WHERE id = ?", (client_id,))
            result = cursor.fetchone()
            admin_conn.close()
            
            if result and result[0]:
                db_path = self.client_databases_path / result[0]
                if db_path.exists():
                    return sqlite3.connect(db_path)
                else:
                    # Try to create the database if it doesn't exist
                    cursor = admin_conn.cursor()
                    cursor.execute("SELECT business_name FROM clients WHERE id = ?", (client_id,))
                    business_result = cursor.fetchone()
                    if business_result:
                        self.create_client_database(client_id, business_result[0])
                        return sqlite3.connect(db_path)
            
            raise ValueError(f"No database found for client {client_id}")
            
        except Exception as e:
            self.logger.error(f"Error getting client connection: {e}")
            raise

    def get_admin_connection(self) -> sqlite3.Connection:
        """Get a connection to the admin database"""
        return sqlite3.connect(self.admin_db_path)

    def execute_client_query(self, client_id: int, query: str, params: tuple = ()) -> List[Dict]:
        """Execute a query on a client's database and return results as list of dicts"""
        try:
            conn = self.get_client_connection(client_id)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            self.logger.error(f"Error executing client query: {e}")
            raise

    def execute_admin_query(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute a query on the admin database and return results as list of dicts"""
        try:
            conn = self.get_admin_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            self.logger.error(f"Error executing admin query: {e}")
            raise

    def insert_scan_result(self, client_id: int, scan_data: Dict[str, Any]) -> int:
        """Insert scan result into client's database"""
        try:
            conn = self.get_client_connection(client_id)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO scans 
                (scanner_id, scan_timestamp, target, scan_type, status, results, 
                 vulnerability_count, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data.get('scanner_id'),
                scan_data.get('scan_timestamp'),
                scan_data.get('target'),
                scan_data.get('scan_type'),
                scan_data.get('status'),
                json.dumps(scan_data.get('results', {})),
                scan_data.get('vulnerability_count', 0),
                scan_data.get('risk_score', 0),
                datetime.now().isoformat()
            ))
            
            scan_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Error inserting scan result: {e}")
            raise

    def insert_lead(self, client_id: int, lead_data: Dict[str, Any]) -> int:
        """Insert lead into client's database"""
        try:
            conn = self.get_client_connection(client_id)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO leads 
                (scanner_id, name, email, company, phone, source, status, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                lead_data.get('scanner_id'),
                lead_data.get('name'),
                lead_data.get('email'),
                lead_data.get('company'),
                lead_data.get('phone'),
                lead_data.get('source', 'scanner'),
                lead_data.get('status', 'new'),
                lead_data.get('notes'),
                datetime.now().isoformat()
            ))
            
            lead_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return lead_id
            
        except Exception as e:
            self.logger.error(f"Error inserting lead: {e}")
            raise

    def get_client_stats(self, client_id: int) -> Dict[str, Any]:
        """Get comprehensive statistics for a client"""
        try:
            conn = self.get_client_connection(client_id)
            cursor = conn.cursor()
            
            # Get scan statistics
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
            completed_scans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM leads")
            total_leads = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM leads WHERE status = 'new'")
            new_leads = cursor.fetchone()[0]
            
            # Get recent activity
            cursor.execute("""
                SELECT scan_timestamp, target, status 
                FROM scans 
                ORDER BY scan_timestamp DESC 
                LIMIT 5
            """)
            recent_scans = cursor.fetchall()
            
            conn.close()
            
            return {
                'total_scans': total_scans,
                'completed_scans': completed_scans,
                'total_leads': total_leads,
                'new_leads': new_leads,
                'recent_scans': recent_scans
            }
            
        except Exception as e:
            self.logger.error(f"Error getting client stats: {e}")
            return {}

    def backup_client_database(self, client_id: int, backup_path: Optional[str] = None) -> str:
        """Create a backup of a client's database"""
        try:
            admin_conn = sqlite3.connect(self.admin_db_path)
            cursor = admin_conn.cursor()
            cursor.execute("SELECT database_name FROM clients WHERE id = ?", (client_id,))
            result = cursor.fetchone()
            admin_conn.close()
            
            if not result or not result[0]:
                raise ValueError(f"No database found for client {client_id}")
            
            source_path = self.client_databases_path / result[0]
            if not backup_path:
                backup_path = f"{source_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Simple file copy for SQLite backup
            import shutil
            shutil.copy2(source_path, backup_path)
            
            self.logger.info(f"Created backup: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            raise

# Global instance
db_manager = DatabaseManager()