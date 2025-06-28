-- Web Lookup Cache Schema
-- Stores results from web-based vulnerability lookups to avoid repeated API calls

CREATE TABLE IF NOT EXISTS web_lookup_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    package_name TEXT,
    source_url TEXT NOT NULL,
    lookup_type TEXT NOT NULL, -- 'debian_backport', 'nvd_details', 'duplicate_check'
    result_data TEXT, -- JSON response
    confidence_score REAL,
    is_vulnerable BOOLEAN,
    fixed_version TEXT,
    lookup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    UNIQUE(cve_id, package_name, lookup_type)
);

-- Index for efficient lookups
CREATE INDEX IF NOT EXISTS idx_web_lookup_cache_cve_package
ON web_lookup_cache(cve_id, package_name, lookup_type);

-- Index for cleanup of expired entries
CREATE INDEX IF NOT EXISTS idx_web_lookup_cache_expires
ON web_lookup_cache(expires_at);
