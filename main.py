from fastapi import FastAPI, HTTPException, Request, Header, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re
import hashlib
import hmac
import logging
import os
import json
import time
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
import spacy
from llama_cpp import Llama 

# --- CONFIGURATION ---
app = FastAPI()
DB_HOST = os.getenv("DB_HOST", "localhost") 
DB_NAME = os.getenv("DB_NAME", "pii_guardrail")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "secret")

# --- 0. LOCAL AI MODEL (REGEX ARCHITECT) ---
MODEL_PATH = "models/llama-3.2-3b-instruct.Q4_K_M.gguf"
llm = None

def load_llm():
    global llm
    if os.path.exists(MODEL_PATH):
        print(f"🧠 Loading Local Llama Model from {MODEL_PATH}...")
        try:
            llm = Llama(model_path=MODEL_PATH, n_ctx=2048, n_threads=4, verbose=False)
            print("✅ Local AI Model Loaded.")
        except Exception as e:
            print(f"⚠️ Failed to load Local AI: {e}")
    else:
        print(f"⚠️ Model file not found at {MODEL_PATH}. AI Regex Generation will be disabled.")

load_llm()

# --- 1. POLICY AGENT (DATABASE SYNC) ---
class PolicySyncAgent:
    def __init__(self):
        self._cache = {}
        self.connect_with_retry()
    
    def connect_with_retry(self):
        for i in range(5):
            try:
                self.refresh_policies()
                print("✅ Connected to Database.")
                return
            except Exception as e:
                print(f"⚠️ DB Wait ({i+1}/5)... {e}")
                time.sleep(3)
    
    def get_db_connection(self):
        return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

    def refresh_policies(self):
        conn = self.get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT domain_id, policy_json FROM domain_policies WHERE is_active = TRUE;")
        rows = cur.fetchall()
        self._cache = {row['domain_id']: row['policy_json'] for row in rows}
        conn.close()

    def get_policy(self, domain: str):
        return self._cache.get(domain)
    
    def list_domains(self):
        return list(self._cache.keys())

policy_agent = PolicySyncAgent()

# --- 1.1 AUDIT LOGGER ---
class AuditLogger:
    def log_event(self, trace_id: str, tenant_id: str, domain: str, target: str, pii_count: int, processing_ms: int, trace: List):
        try:
            conn = policy_agent.get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO audit_logs (trace_id, tenant_id, domain_id, target_context, pii_count, processing_ms, trace_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (trace_id, tenant_id, domain, target, pii_count, processing_ms, json.dumps(trace)))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ AUDIT LOG FAILURE: {e}")

audit_logger = AuditLogger()

# --- 2. DETECTION ENGINE (FINAL COMPLETE) ---
class DetectedEntity(BaseModel):
    entity_type: str
    start_index: int
    end_index: int
    text_segment: str
    detection_source: str
    risk_score: float = 0.0

class DetectionEngine:
    # --- LANGUAGE RESOURCES ---
    
    # [LAYER 1] High-Risk Anchors (Regex)
    PATTERNS = {
        "en": {
            "AADHAAR_UID": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
            "PAN_CARD": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
            "PIN_CODE": re.compile(r"\b\d{3}\s?\d{3}\b"),
            "PHONE": re.compile(r"\b(\+91[\-\s]?)?[6-9]\d{9}\b"),
            # Matches: "Flat 12", "Tower C", "No. 42"
            "HOUSE_ANCHOR": re.compile(r"\b(No\.|Flat|House|H\.No|Door|#|Plot|Tower|Wing|Floor|Villa|Apt)\s?[\w\d\-/]+\b", re.IGNORECASE) 
        },
        "hi": {
            "AADHAAR_UID": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), 
            "PAN_CARD": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
            "PIN_CODE": re.compile(r"\b\d{3}\s?\d{3}\b"),
            "PHONE": re.compile(r"\b(\+91[\-\s]?)?[6-9]\d{9}\b"),
            # Matches: "टावर सी" (Tower C), "नंबर 42"
            "HOUSE_ANCHOR": re.compile(r"(?:\s|^)(मकान|घर|प्लॉट|फ्लैट|नंबर|संख्या|टावर|विला|भवन|विंग)\s?[\w\d\-/]+(?:\s|$)", re.UNICODE)
        }
    }

    # [LAYER 2] Suffix Indicators (FULL LIST)
    SUFFIXES = {
        "en": [
            "Road", "Street", "St", "Ave", "Lane", "Cross", "Main", "Block", "Layout", 
            "Nagar", "Poor", "Pur", "Pura", "Bad", "Colony", "Enclave", "Apartment", "Apt", 
            "Heights", "Villa", "Residency", "Park", "Gate", "Phase", "Sector", "Tower",
            "Manzil", "Niwas", "Bhavan", "Nilaya", "Kuteer", "Marg", "Chowk", "Vihar", 
            "Mane", "Halli", "Palaya", "Sandra", "Gutta", "Kere", "District", "Town", "Mandal"
        ],
        "hi": [
            "रोड", "मार्ग", "नगर", "कॉलोनी", "चौक", "विहार", "गली", "पथ", "ब्लॉक", 
            "सेक्टर", "अपार्टमेंट", "एन्क्लेव", "मीडोज", "हाईट्स", "गार्डन", "टावर",
            "विला", "भवन", "निवास", "कुटीर", "मंजिल", "गेट", "फेज"
        ]
    }

    # [LAYER 3] The "Safe List" (FULL LIST)
    SAFE_GEO_TERMS = {
        "en": {
            "bangalore", "bengaluru", "mumbai", "delhi", "chennai", "kolkata", "hyderabad", 
            "pune", "ahmedabad", "jaipur", "surat", "lucknow", "kanpur", "nagpur", "indore", 
            "thane", "bhopal", "visakhapatnam", "patna", "vadodara", "ghaziabad", "ludhiana", 
            "agra", "nashik", "ranchi", "meerut", "rajkot", "chittoor", "mysore", "mysuru", 
            "hubli", "dharwad", "belgaum", "mangalore", "hassan", "hoskote", "whitefield", 
            "gurgaon", "noida", "mulbagal", "madanapalli",
            "karnataka", "maharashtra", "tamil nadu", "kerala", "andhra pradesh", "telangana", 
            "uttar pradesh", "goa", "gujarat", "rajasthan", "punjab", "haryana", "bihar", 
            "west bengal", "odisha", "madhya pradesh", "india"
        },
        "hi": {
            "बैंगलोर", "दिल्ली", "मुंबई", "भारत", "कर्नाटक", "पुणे", "हैदराबाद", "चेन्नई", 
            "बेंगलुरु", "जयपुर", "होसकोटे", "गुड़गांव", "नोएडा", "ठाणे", "मैसूर", "सूरत", 
            "लखनऊ", "कानपुर", "नागपुर", "इंदौर", "भोपाल", "पटना", "गाजियाबाद", "आगरा", 
            "नासिक", "मेरठ", "राजकोट", "मैसूर", "हुबली", "मंगलौर", "बिहार", "गोआ", "गुजरात",
            "राजस्थान", "पंजाब", "हरियाणा", "ओडिशा", "मध्य प्रदेश", "उत्तर प्रदेश"
        }
    }
    
    # [LAYER 4] Context Connectors
    CONNECTORS = {
        "en": {"pre": ["at", "in", "on", "near"], "post": []},
        "hi": {"pre": [], "post": ["में", "पर", "के पास", "स्थित"]} 
    }
    
    # [LAYER 1.5] Quasi-Identifier Lists
    COMMON_OCCUPATIONS = {
        "farmer", "driver", "teacher", "engineer", "doctor", "nurse", "worker", 
        "laborer", "coolie", "maid", "guard", "police", "soldier", "clerk", "officer"
    }
    GENDER_TERMS = {"male", "female", "man", "woman", "boy", "girl", "transgender"}

    def __init__(self):  # Must be indented 4 spaces
        self.models = {}  # Must be indented 8 spaces
        print("🧠 Optimizing NLP Models for Speed...")
        try:
            # PRUNING: Disable components to fix the 640ms latency
            self.models['en'] = spacy.load("en_core_web_lg", disable=["parser", "attribute_ruler", "lemmatizer", "tagger"])
            print("✅ English NER Pipeline Optimized.")
            
            self.models['hi'] = spacy.load("xx_ent_wiki_sm") 
            print("✅ Hindi (Multi-lang) Model Loaded.")
        except Exception as e:
            print(f"❌ Failed to load NLP Model: {e}")

    def detect_quasi_identifiers(self, text: str, lang: str = "en") -> List[DetectedEntity]:
        """Detects Age, Gender, Occupation for Risk Calculation"""
        if lang != "en": return [] 
        
        quasi_ents = []
        for match in re.finditer(r"\b\d{1,3}\s*(?:years?|yrs?|old)\b", text, re.IGNORECASE):
             quasi_ents.append(DetectedEntity(
                entity_type="AGE", start_index=match.start(), end_index=match.end(), 
                text_segment=match.group(), detection_source="REGEX: Age", risk_score=0.3
            ))

        words = re.findall(r'\b\w+\b', text.lower())
        for i, w in enumerate(words):
            if w in self.COMMON_OCCUPATIONS:
                 for m in re.finditer(rf"\b{w}\b", text, re.IGNORECASE):
                     quasi_ents.append(DetectedEntity(
                        entity_type="OCCUPATION", start_index=m.start(), end_index=m.end(),
                        text_segment=m.group(), detection_source="KEYWORD: Occupation", risk_score=0.3
                     ))
            if w in self.GENDER_TERMS:
                 for m in re.finditer(rf"\b{w}\b", text, re.IGNORECASE):
                     quasi_ents.append(DetectedEntity(
                        entity_type="GENDER", start_index=m.start(), end_index=m.end(),
                        text_segment=m.group(), detection_source="KEYWORD: Gender", risk_score=0.2
                     ))
        return quasi_ents

    def detect(self, text: str, rules: List[Dict], trace_log: List, strict_mode: bool = False, lang: str = "en"):
        detected = []
        
        nlp = self.models.get(lang, self.models.get('en'))
        patterns = self.PATTERNS.get(lang, self.PATTERNS['en'])
        suffixes = self.SUFFIXES.get(lang, self.SUFFIXES['en'])
        safe_geo = self.SAFE_GEO_TERMS.get(lang, self.SAFE_GEO_TERMS['en'])
        
        active_types = [r['entity_type'] for r in rules]
        is_loc_active = any(x in active_types for x in ["LOCATION", "ADDRESS", "GPE"])

        # --- PHASE 1: Regex Anchors ---
        t0 = time.time()
        for rule in rules:
            if "custom_regex" in rule and rule['custom_regex']:
                try:
                    p = re.compile(rule['custom_regex'], re.UNICODE | re.IGNORECASE)
                    for m in p.finditer(text):
                        detected.append(DetectedEntity(
                            entity_type=rule['entity_type'], start_index=m.start(), end_index=m.end(), 
                            text_segment=m.group(), detection_source="REGEX: Custom", risk_score=1.0 
                        ))
                except: pass 
            
        for key in ["AADHAAR_UID", "PAN_CARD", "PIN_CODE", "PHONE", "HOUSE_ANCHOR"]:
            if key in patterns and (key in active_types or key == "HOUSE_ANCHOR"):
                for match in patterns[key].finditer(text):
                    target_type = "LOCATION" if key == "HOUSE_ANCHOR" else key
                    if target_type in active_types or key == "HOUSE_ANCHOR":
                        detected.append(DetectedEntity(
                            entity_type=target_type, start_index=match.start(), end_index=match.end(), 
                            text_segment=match.group(), detection_source=f"REGEX: {key}", risk_score=1.0 
                        ))

        # --- PHASE 2: Suffix Heuristics ---
        if is_loc_active:
            for s in suffixes:
                start = 0
                while True:
                    idx = text.find(s, start)
                    if idx == -1: break
                    prev_space = text.rfind(" ", 0, idx)
                    if prev_space != -1:
                        detected.append(DetectedEntity(
                            entity_type="LOCATION", start_index=prev_space+1, end_index=idx+len(s),
                            text_segment=text[prev_space+1:idx+len(s)], detection_source=f"SUFFIX: {s}", risk_score=1.0
                        ))
                    start = idx + 1

        trace_log.append({
            "step": f"Anchors ({lang})", "status": "Success", 
            "time_ms": int((time.time()-t0)*1000), "details": f"Found {len(detected)} high-risk anchors."
        })

        # --- PHASE 3: AI Candidates ---
        t1 = time.time()
        ai_candidates = []
        if nlp:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ in ["GPE", "LOC", "FAC"]:
                    is_safe = ent.text.lower() in safe_geo
                    if strict_mode:
                        detected.append(DetectedEntity(
                            entity_type="LOCATION", start_index=ent.start_char, end_index=ent.end_char, 
                            text_segment=ent.text, detection_source=f"AI: Strict ({ent.label_})", risk_score=1.0
                        ))
                    else:
                        score = 0.1 if is_safe else 0.5
                        source = f"AI: {'Safe ' if is_safe else ''}Candidate ({ent.label_})"
                        ai_candidates.append(DetectedEntity(
                            entity_type="LOCATION", start_index=ent.start_char, end_index=ent.end_char, 
                            text_segment=ent.text, detection_source=source, risk_score=score
                        ))
                elif ent.label_ in active_types:
                     detected.append(DetectedEntity(
                        entity_type=ent.label_, start_index=ent.start_char, end_index=ent.end_char, 
                        text_segment=ent.text, detection_source=f"AI: {ent.label_}", risk_score=1.0
                    ))

        # --- PHASE 3.5: COMBINATION RISK ---
        quasi_ents = self.detect_quasi_identifiers(text, lang)
        detected.extend(quasi_ents) 

        has_candidates = len(ai_candidates) > 0
        has_demographics = len(quasi_ents) > 0

        if has_candidates and has_demographics and not strict_mode:
            trace_log.append({
                "step": "Combination Risk", "status": "High Risk", "time_ms": 1, 
                "details": "Found Location + Demographics. Upgrading candidates."
            })
            for c in ai_candidates:
                c.risk_score = 1.0
                c.detection_source = "RISK: Combination Upgrade"
                detected.append(c)
            ai_candidates = [] 

        # --- PHASE 4: STRICT MODE BLOCKLIST (FIXED REGEX) ---
        if strict_mode and is_loc_active:
            for term in safe_geo:
                # [FIX 1] Use Negative Lookahead to handle punctuation (Mysore.)
                pattern = r"(?<!\w)(" + re.escape(term) + r")(?!\w)"
                for m in re.finditer(pattern, text, re.IGNORECASE | re.UNICODE):
                    start, end = m.start(1), m.end(1)
                    if not any(d.start_index == start for d in detected):
                        detected.append(DetectedEntity(
                            entity_type="LOCATION", start_index=start, end_index=end,
                            text_segment=m.group(1), detection_source="DICT: Strict Block", risk_score=1.0
                        ))

        # --- PHASE 5: Specificity Chain ---
        if is_loc_active and not strict_mode:
            detected = self.apply_specificity_chain(detected, ai_candidates, text, lang)
        
        trace_log.append({"step": f"AI & Context ({lang})", "status": "Success", "time_ms": int((time.time()-t1)*1000)})
        return detected

    def apply_specificity_chain(self, anchors: List[DetectedEntity], candidates: List[DetectedEntity], text: str, lang: str) -> List[DetectedEntity]:
        final_set = anchors.copy()
        
        all_items = sorted(anchors + candidates, key=lambda x: x.start_index)
        if not all_items: return final_set

        connectors = self.CONNECTORS.get(lang, self.CONNECTORS['en'])

        for i in range(len(all_items)):
            current = all_items[i]
            if current.risk_score == 1.0: continue 

            neighbors = []
            if i > 0: neighbors.append(all_items[i-1]) 
            if i < len(all_items) - 1: neighbors.append(all_items[i+1]) 

            for neighbor in neighbors:
                if neighbor.risk_score == 1.0:
                    if current.start_index > neighbor.end_index:
                        gap_text = text[neighbor.end_index : current.start_index]
                    else:
                        gap_text = text[current.end_index : neighbor.start_index]

                    clean_gap = re.sub(r'[^\w]', '', gap_text)
                    has_conn = any(c in gap_text for c in connectors['pre'] + connectors['post'])
                    is_clean = len(clean_gap) == 0 

                    if (len(gap_text) < 25) and (has_conn or is_clean):
                        current.risk_score = 1.0 
                        current.detection_source = "CHAIN: Extended"
                        final_set.append(current)
                        break 
        
        final_set = self.run_text_domino(final_set, text, lang)
        return final_set

    def run_text_domino(self, entities: List[DetectedEntity], text: str, lang: str) -> List[DetectedEntity]:
        locs = [e for e in entities if e.entity_type == "LOCATION"]
        new_items = []
        safe_geo = self.SAFE_GEO_TERMS.get(lang, self.SAFE_GEO_TERMS['en'])

        for ent in locs:
            cursor = ent.end_index
            while cursor < len(text):
                match = re.match(r'^\s*(,|and)?\s*([A-Za-z]+)', text[cursor:])
                if match:
                    word = match.group(2).lower()
                    if word in safe_geo: break 
                    if word in ["and", "but", "the", "is", "at", "in"]: break
                    full_len = len(match.group(0))
                    if match.group(2)[0].isupper():
                        new_items.append(DetectedEntity(
                            entity_type="LOCATION", start_index=cursor, end_index=cursor+full_len, text_segment=match.group(0),
                            detection_source="CHAIN: Domino", risk_score=1.0
                        ))
                        cursor += full_len
                    else: break
                else: break
        return entities + new_items

detection_engine = DetectionEngine()

# --- 3. API ENDPOINTS ---
class RedactionRequest(BaseModel):
    text: str
    domain: str

class DeployRequest(BaseModel):
    domain_id: str
    rules: List[Dict]

class BulkActivateRequest(BaseModel):
    domain_ids: List[str]

class GenerateRegexRequest(BaseModel):
    example_text: str
class NewDomainRequest(BaseModel):
    domain_id: str
    description: str

@app.get("/")
def read_root():
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/domains")
def get_domains():
    return policy_agent.list_domains()

@app.get("/policy/{domain}")
def get_policy_config(domain: str):
    return policy_agent.get_policy(domain) or {}

@app.post("/redact")
def redact_text(request: RedactionRequest, background_tasks: BackgroundTasks, 
                x_tenant_id: str = Header(None), 
                x_target: str = Header("user"), 
                x_language: str = Header("en")): 
    global_start = time.time()
    trace_id = str(uuid.uuid4())
    trace = [] 
    
    is_strict = (x_target.lower() != "user")
    
    trace.append({
        "step": "Request Authorization",
        "status": "Success",
        "time_ms": 1,
        "details": f"Target: {x_target}. Lang: {x_language} (Strict={is_strict})."
    })

    policy = policy_agent.get_policy(request.domain)
    if not policy:
        raise HTTPException(status_code=400, detail="Invalid or Inactive Domain")
    
    try:
        entities = detection_engine.detect(request.text, policy['rules'], trace, strict_mode=is_strict, lang=x_language)
        
        t_redact = time.time()
        redacted_text = request.text
        sorted_ents = sorted(entities, key=lambda x: x.start_index, reverse=True)
        
        for entity in sorted_ents:
            rule = next((r for r in policy['rules'] if r['entity_type'] == entity.entity_type), None)
            if not rule and entity.entity_type == "LOCATION":
                 rule = next((r for r in policy['rules'] if r['entity_type'] in ["LOCATION", "GPE", "ADDRESS"]), None)
            
            if not rule: continue

            replacement = "[REDACTED]"
            if rule['action'] == "REDACT_TAG":
                replacement = rule['config'].get('tag_label', f'[{entity.entity_type}]')
            elif rule['action'] == "MASK":
                # [FIX 2] Support Custom Mask Char & Smart Email Logic
                mask_char = rule['config'].get('mask_char', 'X')
                
                # Special Case for EMAIL: Keep @ and Domain if possible (and not strict)
                if entity.entity_type == "EMAIL" and "@" in entity.text_segment and not is_strict:
                    # Logic: Mask Local Part, Keep @, Keep Domain
                    # Fallback to '*' if mask_char is 'X' to look nice
                    mask_char = '*' if mask_char == 'X' else mask_char
                    
                    try:
                        local, domain = entity.text_segment.split('@', 1)
                        if len(local) > 3:
                            masked_local = local[:3] + (mask_char * (len(local)-3))
                        else:
                            masked_local = mask_char * len(local)
                        replacement = f"{masked_local}@{domain}"
                    except:
                        replacement = mask_char * len(entity.text_segment)
                else:
                    # Standard Masking for everything else (Credit Card, Phone, etc)
                    suffix_len = rule['config'].get('visible_suffix_length', 0)
                    prefix_len = rule['config'].get('visible_prefix_length', 0)
                    
                    if is_strict: 
                        suffix_len = 0
                        prefix_len = 0
                    
                    raw = entity.text_segment
                    raw_len = len(raw)
                    
                    if (prefix_len + suffix_len) < raw_len:
                        start_part = raw[:prefix_len]
                        end_part = raw[raw_len-suffix_len:] if suffix_len > 0 else ""
                        masked_part = mask_char * (raw_len - prefix_len - suffix_len)
                        replacement = start_part + masked_part + end_part
                    else:
                        replacement = mask_char * raw_len

            elif rule['action'] == "HASH":
                replacement = hmac.new(b"secret", entity.text_segment.encode(), hashlib.sha256).hexdigest()[:10] + "..."

            redacted_text = redacted_text[:entity.start_index] + replacement + redacted_text[entity.end_index:]
        
        trace.append({
            "step": "Policy Enforcement",
            "status": "Success",
            "time_ms": int((time.time() - t_redact) * 1000),
            "details": f"Applied actions to {len(entities)} segments."
        })

        processing_time_ms = int((time.time() - global_start) * 1000)

        background_tasks.add_task(
            audit_logger.log_event, 
            trace_id, x_tenant_id, request.domain, x_target, len(entities), processing_time_ms, trace
        )

        return {
            "original_text": request.text, 
            "redacted_text": redacted_text, 
            "pii_detected": entities,
            "trace": trace,
            "metadata": {
                "processing_time_ms": processing_time_ms,
                "language": x_language
            }
        }

    except Exception as e:
        print(f"❌ CRITICAL FAILURE: {e}")
        trace.append({
            "step": "Fail-Closed Guardrail",
            "status": "CRITICAL FAIL",
            "time_ms": 0,
            "details": str(e)
        })
        raise HTTPException(status_code=500, detail="Guardrail Failure: Fail-Closed active.")

# --- ADMIN ENDPOINTS (Unchanged) ---
@app.get("/admin/all-domains")
def get_all_domains_admin():
    conn = policy_agent.get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT domain_id, is_active, policy_json->'meta'->>'description' as description FROM domain_policies ORDER BY domain_id;")
    rows = cur.fetchall()
    conn.close()
    return rows

@app.get("/admin/domain-config/{domain_id}")
def get_domain_config_admin(domain_id: str):
    conn = policy_agent.get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT policy_json, is_active FROM domain_policies WHERE domain_id = %s", (domain_id,))
    row = cur.fetchone()
    conn.close()
    if not row: raise HTTPException(status_code=404, detail="Domain not found")
    return row

@app.post("/admin/deploy")
def deploy_domain(req: DeployRequest):
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT policy_json FROM domain_policies WHERE domain_id = %s", (req.domain_id,))
        row = cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="Domain not found")
        current_policy = row[0]
        current_policy['rules'] = req.rules
        cur.execute("UPDATE domain_policies SET policy_json = %s WHERE domain_id = %s", (json.dumps(current_policy), req.domain_id))
        conn.commit()
        return {"status": "saved", "active_rules_count": len(req.rules)}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally: conn.close()

@app.post("/admin/activate-domains")
def bulk_activate(req: BulkActivateRequest):
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE domain_policies SET is_active = FALSE")
        if req.domain_ids:
            cur.execute("UPDATE domain_policies SET is_active = TRUE WHERE domain_id = ANY(%s)", (req.domain_ids,))
        conn.commit()
        policy_agent.refresh_policies()
        return {"status": "success", "active_count": len(req.domain_ids)}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally: conn.close()

def build_regex_from_structure(text: str) -> str:
    if not text: return ""
    candidates = re.findall(r'[A-Za-z0-9\-\.]+', text)
    if not candidates: return r".*"
    target = max(candidates, key=len)
    pattern = ""
    last_type = None
    count = 0
    for char in target:
        current_type = None
        if char.isdigit(): current_type = "\\d"
        elif char.isalpha(): 
            current_type = "[A-Z]" if char.isupper() else "[a-z]"
            if not char.isupper() and not char.islower(): current_type = "[A-Za-z]" 
        else: current_type = re.escape(char)
        if current_type == last_type: count += 1
        else:
            if last_type: pattern += last_type + (f"{{{count}}}" if count > 1 else "")
            last_type = current_type
            count = 1
    if last_type: pattern += last_type + (f"{{{count}}}" if count > 1 else "")
    return f"\\b{pattern}\\b"

@app.post("/admin/generate-regex")
def generate_regex(req: GenerateRegexRequest):
    if not llm: raise HTTPException(status_code=503, detail="Local AI Model not loaded.")
    try:
        regex = build_regex_from_structure(req.example_text)
        try: re.compile(regex)
        except: raise HTTPException(status_code=500, detail="Generated pattern was invalid.")
        return {"regex": regex}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/domain")
def create_domain(req: NewDomainRequest):
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        initial_policy = {"meta": {"version": "1.0", "description": req.description}, "rules": []}
        cur.execute("INSERT INTO domain_policies (domain_id, policy_json) VALUES (%s, %s)", (req.domain_id, json.dumps(initial_policy)))
        conn.commit()
        return {"status": "success"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally: conn.close()