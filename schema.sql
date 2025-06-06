-- Main CybrScan database schema
-- Combines functionality from template while maintaining SQLAlchemy compatibility

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS scan_history;
DROP TABLE IF EXISTS customizations;
DROP TABLE IF EXISTS scanners;
DROP TABLE IF EXISTS scans;

-- Main scans table for tracking all scan activities
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    target TEXT,
    results TEXT,
    scanner_id TEXT,
    scan_type TEXT,
    status TEXT DEFAULT 'pending',
    vulnerability_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    completion_time INTEGER DEFAULT 0,
    user_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Clients table to store MSP business information
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    business_name TEXT NOT NULL,
    business_domain TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    contact_phone TEXT,
    scanner_name TEXT,
    subscription_level TEXT DEFAULT 'basic',
    subscription_status TEXT DEFAULT 'active',
    subscription_start TEXT,
    subscription_end TEXT,
    api_key TEXT UNIQUE,
    monthly_scans_used INTEGER DEFAULT 0,
    monthly_scanners_used INTEGER DEFAULT 0,
    last_reset_date TEXT,
    created_at TEXT,
    created_by INTEGER,
    updated_at TEXT,
    updated_by INTEGER,
    active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Enhanced scanners table with comprehensive customization
CREATE TABLE IF NOT EXISTS scanners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    scanner_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    domain TEXT,
    api_key TEXT UNIQUE NOT NULL,
    primary_color TEXT DEFAULT '#02054c',
    secondary_color TEXT DEFAULT '#35a310',
    background_color TEXT DEFAULT '#ffffff',
    text_color TEXT DEFAULT '#333333',
    button_color TEXT DEFAULT '#007bff',
    logo_url TEXT,
    favicon_url TEXT,
    contact_email TEXT,
    contact_phone TEXT,
    business_name TEXT,
    email_subject TEXT DEFAULT 'Your Security Scan Report',
    email_intro TEXT,
    scan_types TEXT,  -- JSON array of enabled scan types
    features TEXT,    -- JSON object of enabled features
    branding TEXT,    -- JSON object for advanced branding
    status TEXT DEFAULT 'active',  -- active, inactive, deleted
    deployment_url TEXT,
    embed_code TEXT,
    created_at TEXT NOT NULL,
    created_by INTEGER,
    updated_at TEXT NOT NULL,
    updated_by INTEGER,
    last_scan_at TEXT,
    total_scans INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Enhanced customizations table for auto-detected and manual branding
CREATE TABLE IF NOT EXISTS customizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    scanner_id TEXT,
    source_url TEXT,  -- URL where colors were extracted from
    primary_color TEXT DEFAULT '#02054c',
    secondary_color TEXT DEFAULT '#35a310',
    background_color TEXT DEFAULT '#ffffff',
    text_color TEXT DEFAULT '#333333',
    accent_color TEXT,
    logo_path TEXT,
    favicon_path TEXT,
    custom_css TEXT,
    font_family TEXT,
    email_subject TEXT DEFAULT 'Your Security Scan Report',
    email_intro TEXT,
    email_signature TEXT,
    auto_detected BOOLEAN DEFAULT 0,
    applied BOOLEAN DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Comprehensive scan history table
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    scan_id TEXT UNIQUE NOT NULL,
    target_url TEXT,
    scan_type TEXT,
    status TEXT DEFAULT 'pending',  -- pending, running, completed, failed
    results TEXT,  -- JSON results
    report_data TEXT,  -- JSON formatted report
    vulnerability_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    scan_duration INTEGER DEFAULT 0,
    user_agent TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (scanner_id) REFERENCES scanners(scanner_id) ON DELETE CASCADE
);

-- Subscription history for tracking changes
CREATE TABLE IF NOT EXISTS subscription_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    old_level TEXT,
    new_level TEXT,
    change_reason TEXT,
    effective_date TEXT NOT NULL,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Lead management for MSP features
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    client_id INTEGER NOT NULL,
    name TEXT,
    email TEXT NOT NULL,
    company TEXT,
    phone TEXT,
    website TEXT,
    source TEXT DEFAULT 'scanner',
    status TEXT DEFAULT 'new',
    priority TEXT DEFAULT 'medium',
    notes TEXT,
    follow_up_date TEXT,
    assigned_to INTEGER,
    scan_results_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (scan_results_id) REFERENCES scans(id)
);

-- System settings and configuration
CREATE TABLE IF NOT EXISTS admin_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'general',
    updated_by INTEGER,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Indexes for optimal performance
CREATE INDEX IF NOT EXISTS idx_scans_scanner_id ON scans(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id);
CREATE INDEX IF NOT EXISTS idx_clients_subscription ON clients(subscription_level);
CREATE INDEX IF NOT EXISTS idx_scanners_client_id ON scanners(client_id);
CREATE INDEX IF NOT EXISTS idx_scanners_scanner_id ON scanners(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanner_id ON scan_history(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(created_at);
CREATE INDEX IF NOT EXISTS idx_leads_scanner_id ON leads(scanner_id);
CREATE INDEX IF NOT EXISTS idx_leads_client_id ON leads(client_id);
CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);