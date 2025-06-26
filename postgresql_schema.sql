-- PostgreSQL Schema for Vulnerability Databases
-- Migration from SQLite to PostgreSQL

-- =====================================================
-- CVE Database Schema (from go-cve-dictionary)
-- =====================================================

CREATE TABLE IF NOT EXISTS fetch_meta_cve (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP,
    go_cve_dict_revision TEXT,
    schema_version INTEGER,
    last_fetched_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_fetch_meta_cve_deleted_at ON fetch_meta_cve(deleted_at);

CREATE TABLE IF NOT EXISTS nvds (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(255),
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nvds_cveid ON nvds(cve_id);

CREATE TABLE IF NOT EXISTS nvd_descriptions (
    id SERIAL PRIMARY KEY,
    nvd_id INTEGER REFERENCES nvds(id),
    lang VARCHAR(255),
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_nvd_descriptions_nvd_id ON nvd_descriptions(nvd_id);

CREATE TABLE IF NOT EXISTS nvd_cvss2_extras (
    id SERIAL PRIMARY KEY,
    nvd_id INTEGER REFERENCES nvds(id),
    source TEXT,
    type VARCHAR(255),
    vector_string VARCHAR(255),
    access_vector VARCHAR(255),
    access_complexity VARCHAR(255),
    authentication VARCHAR(255),
    confidentiality_impact VARCHAR(255),
    integrity_impact VARCHAR(255),
    availability_impact VARCHAR(255),
    base_score REAL,
    severity VARCHAR(255),
    exploitability_score REAL,
    impact_score REAL,
    obtain_all_privilege BOOLEAN,
    obtain_user_privilege BOOLEAN,
    obtain_other_privilege BOOLEAN,
    user_interaction_required BOOLEAN
);

CREATE INDEX IF NOT EXISTS idx_nvd_cvss2_extra_nvd_id ON nvd_cvss2_extras(nvd_id);

CREATE TABLE IF NOT EXISTS nvd_cvss3 (
    id SERIAL PRIMARY KEY,
    nvd_id INTEGER REFERENCES nvds(id),
    source TEXT,
    type VARCHAR(255),
    vector_string VARCHAR(255),
    attack_vector VARCHAR(255),
    attack_complexity VARCHAR(255),
    privileges_required VARCHAR(255),
    user_interaction VARCHAR(255),
    scope VARCHAR(255),
    confidentiality_impact VARCHAR(255),
    integrity_impact VARCHAR(255),
    availability_impact VARCHAR(255),
    base_score REAL,
    base_severity VARCHAR(255),
    exploitability_score REAL,
    impact_score REAL
);

CREATE INDEX IF NOT EXISTS idx_nvd_cvss3_nvd_id ON nvd_cvss3(nvd_id);

CREATE TABLE IF NOT EXISTS nvd_cvss40 (
    id SERIAL PRIMARY KEY,
    nvd_id INTEGER REFERENCES nvds(id),
    source TEXT,
    type VARCHAR(255),
    vector_string VARCHAR(255),
    base_score REAL,
    base_severity VARCHAR(255),
    threat_score REAL,
    threat_severity VARCHAR(255),
    environmental_score REAL,
    environmental_severity VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_nvd_cvss40_nvd_id ON nvd_cvss40(nvd_id);

CREATE TABLE IF NOT EXISTS nvd_cwes (
    id SERIAL PRIMARY KEY,
    nvd_id INTEGER REFERENCES nvds(id),
    source TEXT,
    type VARCHAR(255),
    cwe_id VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_nvd_cwes_nvd_id ON nvd_cwes(nvd_id);

CREATE TABLE IF NOT EXISTS nvd_cpes (
    id SERIAL PRIMARY KEY,
    nvd_id INTEGER REFERENCES nvds(id),
    uri VARCHAR(255),
    formatted_string VARCHAR(255),
    well_formed_name TEXT,
    part VARCHAR(255),
    vendor VARCHAR(255),
    product VARCHAR(255),
    version VARCHAR(255),
    update VARCHAR(255),
    edition VARCHAR(255),
    language VARCHAR(255),
    software_edition VARCHAR(255),
    target_sw VARCHAR(255),
    target_hw VARCHAR(255),
    other VARCHAR(255),
    version_start_excluding VARCHAR(255),
    version_start_including VARCHAR(255),
    version_end_excluding VARCHAR(255),
    version_end_including VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_nvd_cpes_vendor ON nvd_cpes(vendor);
CREATE INDEX IF NOT EXISTS idx_nvd_cpes_part ON nvd_cpes(part);
CREATE INDEX IF NOT EXISTS idx_nvd_cpes_formatted_string ON nvd_cpes(formatted_string);
CREATE INDEX IF NOT EXISTS idx_nvd_cpes_uri ON nvd_cpes(uri);

-- =====================================================
-- OVAL Database Schema (from goval-dictionary)
-- =====================================================

CREATE TABLE IF NOT EXISTS fetch_meta_oval (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP,
    goval_dict_revision TEXT,
    schema_version INTEGER,
    last_fetched_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_fetch_meta_oval_deleted_at ON fetch_meta_oval(deleted_at);

CREATE TABLE IF NOT EXISTS roots (
    id SERIAL PRIMARY KEY,
    family VARCHAR(255),
    os_version VARCHAR(255),
    timestamp TIMESTAMP
);

CREATE TABLE IF NOT EXISTS definitions (
    id SERIAL PRIMARY KEY,
    root_id INTEGER REFERENCES roots(id),
    definition_id VARCHAR(255),
    title TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_definition_root_id ON definitions(root_id);

CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    definition_id INTEGER REFERENCES definitions(id),
    name TEXT,
    version VARCHAR(255),
    arch VARCHAR(255),
    not_fixed_yet BOOLEAN,
    modularity_label VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_definition_id ON packages(definition_id);

CREATE TABLE IF NOT EXISTS references (
    id SERIAL PRIMARY KEY,
    definition_id INTEGER REFERENCES definitions(id),
    source VARCHAR(255),
    ref_id VARCHAR(255),
    ref_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_reference_definition_id ON references(definition_id);

CREATE TABLE IF NOT EXISTS advisories (
    id SERIAL PRIMARY KEY,
    definition_id INTEGER REFERENCES definitions(id),
    severity VARCHAR(255),
    affected_repository VARCHAR(255),
    issued TIMESTAMP,
    updated TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_advisories_definition_id ON advisories(definition_id);

CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    advisory_id INTEGER REFERENCES advisories(id),
    cve_id VARCHAR(255),
    cvss2 VARCHAR(255),
    cvss3 VARCHAR(255),
    cwe VARCHAR(255),
    impact VARCHAR(255),
    href VARCHAR(255),
    public VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_cves_advisory_id ON cves(advisory_id);

CREATE TABLE IF NOT EXISTS bugzillas (
    id SERIAL PRIMARY KEY,
    advisory_id INTEGER REFERENCES advisories(id),
    bugzilla_id VARCHAR(255),
    url VARCHAR(255),
    title VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_bugzillas_advisory_id ON bugzillas(advisory_id);

CREATE TABLE IF NOT EXISTS resolutions (
    id SERIAL PRIMARY KEY,
    advisory_id INTEGER REFERENCES advisories(id),
    state VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_resolution_advisory_id ON resolutions(advisory_id);

CREATE TABLE IF NOT EXISTS components (
    id SERIAL PRIMARY KEY,
    resolution_id INTEGER REFERENCES resolutions(id),
    component VARCHAR(255)
);

-- Additional OVAL tables for Debian-specific data
CREATE TABLE IF NOT EXISTS debians (
    id SERIAL PRIMARY KEY,
    definition_id INTEGER REFERENCES definitions(id)
);

CREATE INDEX IF NOT EXISTS idx_debians_definition_id ON debians(definition_id);

-- =====================================================
-- GOST Database Schema (from gost)
-- =====================================================

CREATE TABLE IF NOT EXISTS fetch_meta_gost (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP,
    gost_revision TEXT,
    schema_version INTEGER,
    last_fetched_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_fetch_meta_gost_deleted_at ON fetch_meta_gost(deleted_at);

-- Ubuntu CVE tables
CREATE TABLE IF NOT EXISTS ubuntu_cves (
    id SERIAL PRIMARY KEY,
    public_date_at_usn TIMESTAMP,
    crd TIMESTAMP,
    candidate VARCHAR(255),
    public_date TIMESTAMP,
    description TEXT,
    ubuntu_description TEXT,
    priority VARCHAR(255),
    discovered_by TEXT,
    assigned_to VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_ubuntu_cve_candidate ON ubuntu_cves(candidate);

CREATE TABLE IF NOT EXISTS ubuntu_patches (
    id SERIAL PRIMARY KEY,
    ubuntu_cve_id INTEGER REFERENCES ubuntu_cves(id),
    package_name VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_ubuntu_patch_package_name ON ubuntu_patches(package_name);
CREATE INDEX IF NOT EXISTS idx_ubuntu_patch_ubuntu_cve_id ON ubuntu_patches(ubuntu_cve_id);

-- Red Hat CVE tables
CREATE TABLE IF NOT EXISTS redhat_cves (
    id SERIAL PRIMARY KEY,
    threat_severity VARCHAR(255),
    public_date TIMESTAMP,
    iava VARCHAR(255),
    cwe VARCHAR(255),
    statement TEXT,
    acknowledgement TEXT,
    mitigation TEXT,
    name VARCHAR(255),
    document_distribution TEXT
);

CREATE INDEX IF NOT EXISTS idx_redhat_cves_name ON redhat_cves(name);

CREATE TABLE IF NOT EXISTS redhat_details (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_redhat_details_redhat_cve_id ON redhat_details(redhat_cve_id);

CREATE TABLE IF NOT EXISTS redhat_references (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    reference TEXT
);

CREATE INDEX IF NOT EXISTS idx_redhat_references_redhat_cve_id ON redhat_references(redhat_cve_id);

CREATE TABLE IF NOT EXISTS redhat_bugzillas (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    description TEXT,
    bugzilla_id VARCHAR(255),
    url VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_redhat_bugzillas_redhat_cve_id ON redhat_bugzillas(redhat_cve_id);

CREATE TABLE IF NOT EXISTS redhat_cvsses (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    cvss_base_score VARCHAR(255),
    cvss_scoring_vector VARCHAR(255),
    status VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_redhat_cvsses_redhat_cve_id ON redhat_cvsses(redhat_cve_id);

CREATE TABLE IF NOT EXISTS redhat_cvss3 (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    cvss3_base_score VARCHAR(255),
    cvss3_scoring_vector VARCHAR(255),
    status VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_redhat_cvss3_redhat_cve_id ON redhat_cvss3(redhat_cve_id);

CREATE TABLE IF NOT EXISTS redhat_affected_releases (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    product_name VARCHAR(255),
    release_date VARCHAR(255),
    advisory VARCHAR(255),
    package VARCHAR(255),
    cpe VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_redhat_affected_releases_redhat_cve_id ON redhat_affected_releases(redhat_cve_id);

CREATE TABLE IF NOT EXISTS redhat_package_states (
    id SERIAL PRIMARY KEY,
    redhat_cve_id INTEGER REFERENCES redhat_cves(id),
    product_name VARCHAR(255),
    fix_state VARCHAR(255),
    package_name VARCHAR(255),
    cpe VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_redhat_package_states_cpe ON redhat_package_states(cpe);
CREATE INDEX IF NOT EXISTS idx_redhat_package_states_package_name ON redhat_package_states(package_name);

-- Additional GOST tables that might exist
CREATE TABLE IF NOT EXISTS debian_cves (
    id SERIAL PRIMARY KEY,
    package VARCHAR(255),
    cve_id VARCHAR(255),
    fixed_version VARCHAR(255),
    urgency VARCHAR(255),
    remote VARCHAR(255),
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_debian_cves_package ON debian_cves(package);
CREATE INDEX IF NOT EXISTS idx_debian_cves_cve_id ON debian_cves(cve_id);

-- Microsoft-related tables (if present)
CREATE TABLE IF NOT EXISTS microsoft_cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(255),
    impact VARCHAR(255),
    severity VARCHAR(255),
    exploitability VARCHAR(255),
    vector VARCHAR(255),
    complexity VARCHAR(255),
    authentication VARCHAR(255),
    confidentiality_impact VARCHAR(255),
    integrity_impact VARCHAR(255),
    availability_impact VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_microsoft_cves_cve_id ON microsoft_cves(cve_id);

-- Performance optimization indexes
CREATE INDEX IF NOT EXISTS idx_nvds_published_date ON nvds(published_date);
CREATE INDEX IF NOT EXISTS idx_ubuntu_cves_public_date ON ubuntu_cves(public_date);
CREATE INDEX IF NOT EXISTS idx_redhat_cves_public_date ON redhat_cves(public_date);
CREATE INDEX IF NOT EXISTS idx_definitions_definition_id ON definitions(definition_id);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_packages_name_version ON packages(name, version);
CREATE INDEX IF NOT EXISTS idx_ubuntu_patches_package_cve ON ubuntu_patches(package_name, ubuntu_cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_descriptions_lang_nvd ON nvd_descriptions(lang, nvd_id);
