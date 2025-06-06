-- Template for individual client databases
-- This schema is used to create isolated databases for each client
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    results TEXT,  -- JSON formatted results
    report_path TEXT,
    created_at TEXT,
    vulnerability_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    completion_time INTEGER DEFAULT 0,
    scan_duration INTEGER DEFAULT 0
);

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
    notes TEXT,
    follow_up_date TEXT,
    priority TEXT DEFAULT 'medium',
    assigned_to TEXT
);

CREATE TABLE IF NOT EXISTS scan_configurations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    configuration TEXT NOT NULL,  -- JSON formatted configuration
    is_default BOOLEAN DEFAULT 0,
    created_at TEXT,
    updated_at TEXT,
    scan_types TEXT,  -- JSON array of enabled scan types
    notification_settings TEXT  -- JSON notification preferences
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    report_type TEXT NOT NULL, -- summary, detailed, executive
    report_data TEXT NOT NULL, -- JSON formatted report
    generated_at TEXT NOT NULL,
    expires_at TEXT,
    access_count INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL, -- scan_complete, lead_captured, error
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    read_status INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    related_id INTEGER,
    related_type TEXT
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_scans_scanner ON scans(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_leads_scanner ON leads(scanner_id);
CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type);