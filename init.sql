-- FILE: init.sql

-- 1. Create the Table
-- [CHANGE] Default is_active is now FALSE (Clean Slate Protocol)
CREATE TABLE IF NOT EXISTS domain_policies (
    domain_id VARCHAR(50) PRIMARY KEY,
    is_active BOOLEAN DEFAULT FALSE, 
    policy_json JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. SEED DATA (All 6 Domains - Inactive by Default)

-- (A) EDUCATION DOMAIN
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'education', FALSE,
    '{
        "meta": {"version": "1.0", "description": "Student & University Data"},
        "rules": [
            { "entity_type": "STUDENT_ID", "action": "REDACT_TAG", "config": {"tag_label": "[STUDENT_ID]"}, "custom_regex": "\\b[A-Z]{2,5}\\d{4,10}\\b" },
            { "entity_type": "STUDENT_NAME", "action": "HASH", "config": {"algorithm": "HMAC-SHA256"}, "custom_regex": "\\b[A-Z][a-z]+(?:\\s[A-Z][a-z]+){1,3}\\b" },
            { "entity_type": "EMAIL", "action": "MASK", "config": {"mask_char": "*", "visible_prefix_length": 3}, "custom_regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b" },
            { "entity_type": "PHONE", "action": "MASK", "config": {"visible_suffix_length": 2}, "custom_regex": "\\b(?:\\+?\\d{1,3}[\\s-]?)?\\d{10}\\b" }
        ]
    }'
);

-- (B) FINANCE / BANKING DOMAIN
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'finance', FALSE,
    '{
        "meta": {"version": "1.0", "description": "Banking & PCI-DSS Compliance"},
        "rules": [
            { "entity_type": "BANK_ACCT", "action": "MASK", "config": {"visible_suffix_length": 4}, "custom_regex": "\\b\\d{9,18}\\b" },
            { "entity_type": "CREDIT_CARD", "action": "REDACT_TAG", "config": {"tag_label": "[PCI_DATA]"}, "custom_regex": "\\b(?:\\d[ -]*?){13,16}\\b" },
            { "entity_type": "IFSC_CODE", "action": "REDACT_TAG", "config": {"tag_label": "[IFSC]"}, "custom_regex": "\\b[A-Z]{4}0[A-Z0-9]{6}\\b" },
            { "entity_type": "PAN_CARD", "action": "MASK", "config": {"visible_suffix_length": 2}, "custom_regex": "\\b[A-Z]{5}\\d{4}[A-Z]\\b" },
            { "entity_type": "UPI_ID", "action": "HASH", "config": {"algorithm": "HMAC-SHA256"}, "custom_regex": "\\b[\\w.-]+@[\\w.-]+\\b" }
        ]
    }'
);

-- (C) HEALTHCARE DOMAIN
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'healthcare', FALSE,
    '{
        "meta": {"version": "1.0", "description": "HIPAA & Patient Records"},
        "rules": [
            { "entity_type": "MEDICAL_MRN", "action": "REDACT_TAG", "config": {"tag_label": "[MRN]"}, "custom_regex": "\\b[A-Z]{2,5}\\d{4,10}\\b" },
            { "entity_type": "INSURANCE_ID", "action": "MASK", "config": {"visible_suffix_length": 3}, "custom_regex": "\\b[A-Z0-9]{6,20}\\b" },
            { "entity_type": "ICD10_CODE", "action": "REDACT_TAG", "config": {"tag_label": "[DIAGNOSIS]"}, "custom_regex": "\\b[A-TV-Z][0-9]{2}(\\.[0-9A-TV-Z]{1,4})?\\b" },
            { "entity_type": "AADHAAR_UID", "action": "MASK", "config": {"mask_char": "X", "visible_suffix_length": 4}, "custom_regex": "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b" }
        ]
    }'
);

-- (D) GOVERNMENT / IDENTITY DOMAIN
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'government', FALSE,
    '{
        "meta": {"version": "1.0", "description": "National ID & Citizen Data"},
        "rules": [
            { "entity_type": "AADHAAR_UID", "action": "MASK", "config": {"visible_suffix_length": 4}, "custom_regex": "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b" },
            { "entity_type": "PASSPORT", "action": "MASK", "config": {"visible_suffix_length": 2}, "custom_regex": "\\b[A-PR-WY][1-9]\\d{6}\\b" },
            { "entity_type": "VOTER_ID", "action": "HASH", "config": {"algorithm": "HMAC-SHA256"}, "custom_regex": "\\b[A-Z]{3}\\d{7}\\b" },
            { "entity_type": "DRIVING_LIC", "action": "REDACT_TAG", "config": {"tag_label": "[DL_NO]"}, "custom_regex": "\\b[A-Z]{2}\\d{2}\\d{4}\\d{7}\\b" },
            { "entity_type": "RATION_CARD", "action": "MASK", "config": {"visible_suffix_length": 3}, "custom_regex": "\\b[A-Z]\\d{9}\\b" }
        ]
    }'
);

-- (E) EMPLOYMENT / HR DOMAIN
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'employment', FALSE,
    '{
        "meta": {"version": "1.0", "description": "Internal Employee & Payroll Data"},
        "rules": [
            { "entity_type": "EMPLOYEE_ID", "action": "REDACT_TAG", "config": {"tag_label": "[EMP_ID]"}, "custom_regex": "\\b[A-Z]{2,5}\\d{3,10}\\b" },
            { "entity_type": "SALARY", "action": "REDACT_TAG", "config": {"tag_label": "[SALARY_HIDDEN]"}, "custom_regex": "₹?\\s?\\d{1,3}(?:,\\d{3})*(?:\\.\\d{1,2})?" },
            { "entity_type": "OFFICIAL_EMAIL", "action": "MASK", "config": {"visible_prefix_length": 3}, "custom_regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b" },
            { "entity_type": "BANK_ACCT", "action": "MASK", "config": {"visible_suffix_length": 4}, "custom_regex": "\\b\\d{9,18}\\b" }
        ]
    }'
);

-- (F) DIGITAL / ONLINE PLATFORMS
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'digital', FALSE,
    '{
        "meta": {"version": "1.0", "description": "Credentials & Network Identifiers"},
        "rules": [
            { "entity_type": "USERNAME", "action": "REDACT_TAG", "config": {"tag_label": "[USER]"}, "custom_regex": "\\b[a-zA-Z0-9._-]{3,20}\\b" },
            { "entity_type": "IP_ADDRESS", "action": "REDACT_TAG", "config": {"tag_label": "[IP]"}, "custom_regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b" },
            { "entity_type": "MAC_ADDR", "action": "REDACT_TAG", "config": {"tag_label": "[MAC]"}, "custom_regex": "\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b" },
            { "entity_type": "API_KEY", "action": "HASH", "config": {"algorithm": "HMAC-SHA256"}, "custom_regex": "\\b[A-Za-z0-9_\\-]{20,}\\b" },
            { "entity_type": "PASSWORD", "action": "REDACT_TAG", "config": {"tag_label": "[PWD_REMOVED]"}, "custom_regex": "(?i)(password\\s*[:=]\\s*\\S+)" }
        ]
    }'
);