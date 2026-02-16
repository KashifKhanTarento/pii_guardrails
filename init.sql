-- FILE: init.sql (Final Summit Configuration)

-- 1. TABLES
CREATE TABLE IF NOT EXISTS pattern_library (
    id SERIAL PRIMARY KEY,
    entity_label VARCHAR(50) NOT NULL,
    lang_code VARCHAR(10) NOT NULL,
    regex_pattern TEXT NOT NULL,
    risk_score FLOAT DEFAULT 1.0,
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(entity_label, lang_code)
);

CREATE TABLE IF NOT EXISTS geo_library (
    id SERIAL PRIMARY KEY,
    term_text VARCHAR(100) NOT NULL,
    lang_code VARCHAR(10) NOT NULL,
    term_type VARCHAR(20) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS keyword_library (
    id SERIAL PRIMARY KEY,
    word_text VARCHAR(100) NOT NULL,
    category VARCHAR(20) NOT NULL,
    lang_code VARCHAR(10) NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_policies (
    domain_id VARCHAR(50) PRIMARY KEY,
    is_active BOOLEAN DEFAULT FALSE, 
    policy_json JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    trace_id UUID,
    tenant_id VARCHAR(50),
    domain_id VARCHAR(50),
    target_context VARCHAR(20),
    pii_count INT,
    processing_ms INT,
    trace_json JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. SEED DATA: PATTERNS
INSERT INTO pattern_library (entity_label, lang_code, regex_pattern) VALUES
('AADHAAR_UID', 'all', '\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
('PAN_CARD', 'all', '\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'),
('PIN_CODE', 'all', '\b\d{3}\s?\d{3}\b'),
('PHONE', 'all', '\b(\+91[\-\s]?)?[6-9]\d{9}\b'),
('EMAIL', 'all', '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
('CREDIT_CARD', 'all', '\b(?:\d[ -]*?){13,16}\b'),
-- Names
('PERSON', 'en', '(?i)\b(?:Name|Mr\.|Ms\.|Mrs\.)\s+(?:is\s+)?[:\-]?\s*([A-Z][a-z]+)'),
('PERSON', 'hi', '(?:\s|^)(?:नाम|इसम)\s*[:\-]?\s*([\w\u0900-\u097F]+)'),
('PERSON', 'mr', '(?:\s|^)(?:नाव)\s*[:\-]?\s*([\w\u0900-\u097F]+)'),
('PERSON', 'ta', '(?:\s|^)(?:பெயர்)\s*[:\-]?\s*([\w\u0B80-\u0BFF]+)'),
-- Anchors (Includes 'Address' fix)
('HOUSE_ANCHOR', 'en', '\b(Address|No\.|Flat|House|H\.No|Door|#|Plot|Tower|Wing|Floor|Villa|Apt)\s?[\w\d\-/.,]+\b'),
('HOUSE_ANCHOR', 'hi', '(?:\s|^)(पता|मकान|घर|प्लॉट|फ्लैट|नंबर|संख्या|टावर|विला|भवन|विंग)\s?[\w\d\-/.,]+(?:\s|$)'),
('HOUSE_ANCHOR', 'mr', '(?:\s|^)(घर|सदन|निवास|इमारत|फ्लॅट|अपार्टमेंट|नंबर|क्रमांक|चाळ|खोली|गाळा)\s?[\w\d\-/.,]+(?:\s|$)'),
('HOUSE_ANCHOR', 'ta', '(?:\s|^)(வீடு|வீட்டு|எண்|மனை|தளம்|கதவு|பிளாட்|டவர்|வில்லா)\s?[\w\d\-/.,]+(?:\s|[.,]|$)')
ON CONFLICT (entity_label, lang_code) DO UPDATE SET regex_pattern = EXCLUDED.regex_pattern;

-- 3. SEED DATA: GEO & KEYWORDS
INSERT INTO geo_library (term_text, lang_code, term_type) VALUES
('Road', 'en', 'SUFFIX'), ('Street', 'en', 'SUFFIX'), ('Nagar', 'en', 'SUFFIX'), ('Colony', 'en', 'SUFFIX'),
('Cross', 'en', 'SUFFIX'), ('Main', 'en', 'SUFFIX'), ('Block', 'en', 'SUFFIX'), ('Layout', 'en', 'SUFFIX'),
('Bangalore', 'en', 'SAFE_CITY'), ('Mumbai', 'en', 'SAFE_CITY'), ('Delhi', 'en', 'SAFE_CITY'), 
('Chennai', 'en', 'SAFE_CITY'), ('Pune', 'en', 'SAFE_CITY'), ('Hyderabad', 'en', 'SAFE_CITY'), ('Koramangala', 'en', 'SAFE_CITY'),
('रोड', 'hi', 'SUFFIX'), ('नगर', 'hi', 'SUFFIX'), ('मार्ग', 'hi', 'SUFFIX'), ('चौक', 'hi', 'SUFFIX'),
('बैंगलोर', 'hi', 'SAFE_CITY'), ('मुंबई', 'hi', 'SAFE_CITY'), ('दिल्ली', 'hi', 'SAFE_CITY'), ('कोरमंगला', 'hi', 'SAFE_CITY'),
('रोड', 'mr', 'SUFFIX'), ('मार्ग', 'mr', 'SUFFIX'), ('नगर', 'mr', 'SUFFIX'), ('पेठ', 'mr', 'SUFFIX'), 
('आळी', 'mr', 'SUFFIX'), ('वाडा', 'mr', 'SUFFIX'), ('गल्ली', 'mr', 'SUFFIX'),
('पुणे', 'mr', 'SAFE_CITY'), ('मुंबई', 'mr', 'SAFE_CITY'), ('नागपूर', 'mr', 'SAFE_CITY'),
('சாலை', 'ta', 'SUFFIX'), ('தெரு', 'ta', 'SUFFIX'), ('நகர்', 'ta', 'SUFFIX'), 
('சென்னை', 'ta', 'SAFE_CITY'), ('பெங்களூரு', 'ta', 'SAFE_CITY'), ('மதுரை', 'ta', 'SAFE_CITY');

INSERT INTO keyword_library (word_text, lang_code, category) VALUES
('farmer', 'en', 'OCCUPATION'), ('doctor', 'en', 'OCCUPATION'), ('driver', 'en', 'OCCUPATION'),
('male', 'en', 'GENDER'), ('female', 'en', 'GENDER');

-- 4. DOMAIN POLICIES

-- (A) LOGISTICS (English/Global) - THE HERO DOMAIN
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'logistics', TRUE,
    '{
        "meta": {"version": "3.0", "description": "Global Logistics (Full PII Suite)"},
        "rules": [
            { "entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[NAME]"} },
            { "entity_type": "LOCATION", "action": "REDACT_TAG", "config": {"tag_label": "[LOC]"} },
            { "entity_type": "HOUSE_ANCHOR", "action": "REDACT_TAG", "config": {"tag_label": "[ADDRESS]"} },
            { "entity_type": "AADHAAR_UID", "action": "MASK", "config": {"visible_suffix_length": 4} },
            { "entity_type": "EMAIL", "action": "REDACT_TAG", "config": {"tag_label": "[EMAIL]"} },
            { "entity_type": "PHONE", "action": "HASH", "config": {} },
            { "entity_type": "PIN_CODE", "action": "REDACT_TAG", "config": {"tag_label": "[PIN]"} }
        ]
    }'
);

-- (B) HINDI LOGISTICS (Full PII)
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'logistics_hindi', TRUE,
    '{
        "meta": {"version": "2.0", "description": "Hindi Logistics"},
        "rules": [
            { "entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[नाम]"} },
            { "entity_type": "EMAIL", "action": "REDACT_TAG", "config": {"tag_label": "[ईमेल]"} },
            { "entity_type": "HOUSE_ANCHOR", "action": "REDACT_TAG", "config": {"tag_label": "[घर नंबर]"} },
            { "entity_type": "LOCATION", "action": "REDACT_TAG", "config": {"tag_label": "[स्थान]"} },
            { "entity_type": "PIN_CODE", "action": "REDACT_TAG", "config": {"tag_label": "[पिन कोड]"} },
            { "entity_type": "PHONE", "action": "HASH", "config": {} },
            { "entity_type": "AADHAAR_UID", "action": "MASK", "config": {"visible_suffix_length": 4} }
        ]
    }'
);

-- (C) MARATHI LOGISTICS (Full PII)
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'logistics_marathi', TRUE,
    '{
        "meta": {"version": "2.0", "description": "Marathi Logistics"},
        "rules": [
            { "entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[नाव]"} },
            { "entity_type": "EMAIL", "action": "REDACT_TAG", "config": {"tag_label": "[ईमेल]"} },
            { "entity_type": "HOUSE_ANCHOR", "action": "REDACT_TAG", "config": {"tag_label": "[घर क्रमांक]"} },
            { "entity_type": "LOCATION", "action": "REDACT_TAG", "config": {"tag_label": "[स्थान]"} },
            { "entity_type": "PIN_CODE", "action": "REDACT_TAG", "config": {"tag_label": "[पिन कोड]"} },
            { "entity_type": "PHONE", "action": "HASH", "config": {} }
        ]
    }'
);

-- (D) TAMIL LOGISTICS (Full PII)
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES (
    'logistics_tamil', TRUE,
    '{
        "meta": {"version": "2.0", "description": "Tamil Logistics"},
        "rules": [
            { "entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[பெயர்]"} },
            { "entity_type": "EMAIL", "action": "REDACT_TAG", "config": {"tag_label": "[மின்னஞ்சல்]"} },
            { "entity_type": "HOUSE_ANCHOR", "action": "REDACT_TAG", "config": {"tag_label": "[வீட்டு எண்]"} },
            { "entity_type": "LOCATION", "action": "REDACT_TAG", "config": {"tag_label": "[முகவரி]"} },
            { "entity_type": "PIN_CODE", "action": "REDACT_TAG", "config": {"tag_label": "[அஞ்சல் குறியீடு]"} },
            { "entity_type": "PHONE", "action": "HASH", "config": {} }
        ]
    }'
);

-- (E) ORIGINAL 6 SEED DOMAINS
INSERT INTO domain_policies (domain_id, is_active, policy_json) VALUES 
('healthcare', TRUE, '{"meta": {"version": "2.0", "description": "HIPAA/Patient Records"}, "rules": [{"entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[PATIENT]"}}, {"entity_type": "AADHAAR_UID", "action": "MASK", "config": {"visible_suffix_length": 4}}]}'),
('finance', TRUE, '{"meta": {"version": "2.0", "description": "Banking & PCI-DSS"}, "rules": [{"entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[NAME]"}}, {"entity_type": "PAN_CARD", "action": "MASK", "config": {"visible_suffix_length": 2}}]}'),
('education', TRUE, '{"meta": {"version": "2.0", "description": "Student Data"}, "rules": [{"entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[STUDENT]"}}, {"entity_type": "EMAIL", "action": "MASK", "config": {"visible_prefix_length": 3}}]}'),
('government', TRUE, '{"meta": {"version": "2.0", "description": "Citizen Data Services"}, "rules": [{"entity_type": "AADHAAR_UID", "action": "MASK", "config": {"visible_suffix_length": 4}}]}'),
('employment', TRUE, '{"meta": {"version": "2.0", "description": "HR & Payroll"}, "rules": [{"entity_type": "PERSON", "action": "REDACT_TAG", "config": {"tag_label": "[EMPLOYEE]"}}, {"entity_type": "EMAIL", "action": "MASK", "config": {"visible_prefix_length": 3}}]}'),
('digital', TRUE, '{"meta": {"version": "2.0", "description": "Digital Identity"}, "rules": [{"entity_type": "EMAIL", "action": "MASK", "config": {"visible_prefix_length": 3}}, {"entity_type": "IP_ADDRESS", "action": "REDACT_TAG", "config": {"tag_label": "[IP]"}}]}')
ON CONFLICT (domain_id) DO UPDATE SET is_active = TRUE, policy_json = EXCLUDED.policy_json;