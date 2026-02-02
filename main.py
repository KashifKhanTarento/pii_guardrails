from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import re
import hashlib
import hmac
import logging
import os
import json
import time
import psycopg2
from psycopg2.extras import RealDictCursor
import spacy
from llama_cpp import Llama  # NEW: Local AI Library

# --- CONFIG ---
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

# Load on startup
load_llm()

# --- 1. POLICY AGENT (DB SYNC) ---
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
        # Only fetch ACTIVE policies for the cache (Playground usage)
        cur.execute("SELECT domain_id, policy_json FROM domain_policies WHERE is_active = TRUE;")
        rows = cur.fetchall()
        self._cache = {row['domain_id']: row['policy_json'] for row in rows}
        conn.close()

    def get_policy(self, domain: str):
        return self._cache.get(domain)
    
    def list_domains(self):
        return list(self._cache.keys())

policy_agent = PolicySyncAgent()

# --- 2. DETECTION ENGINE (HYBRID) ---
class DetectedEntity(BaseModel):
    entity_type: str
    start_index: int
    end_index: int
    text_segment: str
    detection_source: str

class DetectionEngine:
    STATIC_PATTERNS = {
        "AADHAAR_UID": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        "PAN_CARD": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    }

    def __init__(self):
        print("🧠 Loading NLP Model...")
        try:
            self.nlp = spacy.load("en_core_web_lg")
            print("✅ NLP Model Loaded.")
        except Exception as e:
            print(f"❌ Failed to load NLP Model: {e}")
            self.nlp = None

    def detect(self, text: str, rules: List[Dict]):
        detected = []
        
        # --- CONFIG: Generic Keyword Mappings ---
        # This allows future domains to work automatically.
        # If Spacy finds "PERSON", we look for active rules containing "NAME", "STUDENT", "CLIENT", etc.
        AI_MAPPINGS = {
            "PERSON": ["PERSON", "NAME", "STUDENT", "CLIENT", "PATIENT", "EMPLOYEE", "SUSPECT", "VICTIM"],
            "GPE": ["LOCATION", "CITY", "COUNTRY", "STATE", "PLACE", "ORIGIN", "DESTINATION"],
            "ORG": ["ORG", "COMPANY", "BANK", "HOSPITAL", "AGENCY", "FIRM"]
        }

        # PHASE 1: Regex (Custom & Static)
        # (This part remains unchanged)
        for rule in rules:
            e_type = rule['entity_type']
            pattern = None
            source_label = "REGEX: Static"
            
            if "custom_regex" in rule and rule['custom_regex']:
                try:
                    pattern = re.compile(rule['custom_regex'])
                    source_label = f"REGEX: Custom ({e_type})"
                except re.error:
                    print(f"❌ Bad Regex for {e_type}")
            elif e_type in self.STATIC_PATTERNS:
                pattern = self.STATIC_PATTERNS[e_type]

            if pattern:
                for match in pattern.finditer(text):
                    detected.append(DetectedEntity(
                        entity_type=e_type, 
                        start_index=match.start(), 
                        end_index=match.end(), 
                        text_segment=match.group(),
                        detection_source=source_label
                    ))

        # PHASE 2: AI Model (Generic Activation)
        active_entities = [r['entity_type'] for r in rules]
        
        # [SMART FIX] Check if ANY active rule matches ANY keyword in our MAPPINGS
        # This ensures the AI turns on for new rules like "CLIENT_NAME" automatically.
        all_keywords = [kw for valid_list in AI_MAPPINGS.values() for kw in valid_list]
        needs_ai = any(kw in rule_name.upper() for rule_name in active_entities for kw in all_keywords)

        if self.nlp and needs_ai:
            doc = self.nlp(text)
            for ent in doc.ents:
                mapped_type = None
                
                # Check if the Spacy label (PERSON/GPE/ORG) has a corresponding rule active
                if ent.label_ in AI_MAPPINGS:
                    # Look for the best matching active rule
                    # e.g. If Spacy found PERSON, and "STUDENT_NAME" is active, it matches "NAME" keyword.
                    potential_keywords = AI_MAPPINGS[ent.label_]
                    
                    # 1. Try exact match first (e.g. Rule "PERSON" exists)
                    if ent.label_ in active_entities:
                        mapped_type = ent.label_
                    else:
                        # 2. Fuzzy match: Find first active rule that contains a relevant keyword
                        # e.g. "STUDENT_NAME" contains "NAME" -> Match found!
                        for rule_name in active_entities:
                            if any(kw in rule_name.upper() for kw in potential_keywords):
                                mapped_type = rule_name
                                break
                
                if mapped_type:
                    detected.append(DetectedEntity(
                        entity_type=mapped_type,
                        start_index=ent.start_char,
                        end_index=ent.end_char,
                        text_segment=ent.text,
                        detection_source=f"AI: NER Model ({ent.label_} -> {mapped_type})"
                    ))

        return detected

detection_engine = DetectionEngine()

# --- 3. API ENDPOINTS ---
class RedactionRequest(BaseModel):
    text: str
    domain: str

class GenerateRegexRequest(BaseModel):
    example_text: str

class NewDomainRequest(BaseModel):
    domain_id: str
    description: str

class NewRuleRequest(BaseModel):
    domain_id: str
    entity_type: str
    action: str 
    config: Dict
    custom_regex: Optional[str] = None

class DeployRequest(BaseModel):
    domain_id: str
    rules: List[Dict]

@app.get("/")
def read_root():
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/domains")
def get_domains():
    # Returns only ACTIVE domains (for Playground)
    return policy_agent.list_domains()

@app.get("/policy/{domain}")
def get_policy_config(domain: str):
    return policy_agent.get_policy(domain) or {}

@app.post("/redact")
def redact_text(request: RedactionRequest, x_tenant_id: str = Header(None)):
    start_time = time.time()
    
    policy = policy_agent.get_policy(request.domain)
    if not policy:
        raise HTTPException(status_code=400, detail="Invalid or Inactive Domain")

    try:
        entities = detection_engine.detect(request.text, policy['rules'])
        
        redacted_text = request.text
        for entity in sorted(entities, key=lambda x: x.start_index, reverse=True):
            rule = next((r for r in policy['rules'] if r['entity_type'] == entity.entity_type), None)
            if not rule: continue

            replacement = "[REDACTED]"
            if rule['action'] == "REDACT_TAG":
                replacement = rule['config'].get('tag_label', f'[{entity.entity_type}]')
            elif rule['action'] == "MASK":
                visible = rule['config'].get('visible_suffix_length', 0)
                raw = entity.text_segment
                
                # [FIX] Handle visible=0 explicitly to prevent Python [-0:] slicing bug
                if visible > 0:
                    if len(raw) > visible:
                        replacement = "X" * (len(raw) - visible) + raw[-visible:]
                    else:
                        replacement = "X" * len(raw) # Text shorter than visible length
                else:
                    replacement = "X" * len(raw) # Fully masked
            elif rule['action'] == "HASH":
                replacement = hmac.new(b"secret", entity.text_segment.encode(), hashlib.sha256).hexdigest()[:10] + "..."

            redacted_text = redacted_text[:entity.start_index] + replacement + redacted_text[entity.end_index:]

        processing_time_ms = int((time.time() - start_time) * 1000)

        return {
            "original_text": request.text, 
            "redacted_text": redacted_text, 
            "pii_detected": entities,
            "metadata": {
                "processing_time_ms": processing_time_ms,
                "tenant_id": x_tenant_id,
                "engine_version": "2.1.0 (AI-Ready)"
            }
        }

    except Exception as e:
        print(f"❌ CRITICAL FAILURE: {e}")
        raise HTTPException(status_code=500, detail="Guardrail Failure: Fail-Closed active.")

# --- ADMIN ENDPOINTS (NEW) ---

@app.get("/admin/all-domains")
def get_all_domains_admin():
    """Fetch ALL domains (Active & Inactive) for Admin Panel"""
    conn = policy_agent.get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT domain_id, is_active, policy_json->'meta'->>'description' as description FROM domain_policies;")
    rows = cur.fetchall()
    conn.close()
    return rows

@app.get("/admin/domain-config/{domain_id}")
def get_domain_config_admin(domain_id: str):
    """Fetch config for a specific domain to populate the editor"""
    conn = policy_agent.get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT policy_json, is_active FROM domain_policies WHERE domain_id = %s", (domain_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Domain not found")
    return row

@app.post("/admin/deploy")
def deploy_domain(req: DeployRequest):
    """Save the selected rules and ACTIVATE the domain"""
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT policy_json FROM domain_policies WHERE domain_id = %s", (req.domain_id,))
        row = cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="Domain not found")
        
        current_policy = row[0]
        # Overwrite 'rules' with the admin's checklist
        current_policy['rules'] = req.rules
        
        cur.execute("UPDATE domain_policies SET policy_json = %s, is_active = TRUE WHERE domain_id = %s", 
                    (json.dumps(current_policy), req.domain_id))
        conn.commit()
        
        policy_agent.refresh_policies()
        return {"status": "deployed", "active_rules_count": len(req.rules)}
    except Exception as e:
        conn.rollback()
        print(f"Deploy Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# --- HELPER LOGIC ---

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
        if char.isdigit(): 
            current_type = "\\d"
        elif char.isalpha(): 
            current_type = "[A-Z]" if char.isupper() else "[a-z]"
            if not char.isupper() and not char.islower(): current_type = "[A-Za-z]" 
        else: 
            current_type = re.escape(char)
        
        if current_type == last_type:
            count += 1
        else:
            if last_type:
                pattern += last_type + (f"{{{count}}}" if count > 1 else "")
            last_type = current_type
            count = 1
            
    if last_type:
        pattern += last_type + (f"{{{count}}}" if count > 1 else "")

    return f"\\b{pattern}\\b"

@app.post("/admin/generate-regex")
def generate_regex(req: GenerateRegexRequest):
    if not llm:
        raise HTTPException(status_code=503, detail="Local AI Model not loaded.")
    try:
        start = time.time()
        regex = build_regex_from_structure(req.example_text)
        try:
            re.compile(regex)
        except re.error:
            raise HTTPException(status_code=500, detail="Generated pattern was invalid.")
        return {"regex": regex, "latency_ms": int((time.time() - start) * 1000)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/domain")
def create_domain(req: NewDomainRequest):
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        initial_policy = {"meta": {"version": "1.0", "description": req.description}, "rules": []}
        # Note: Database defaults is_active to FALSE, so this new domain starts inactive
        cur.execute("INSERT INTO domain_policies (domain_id, policy_json) VALUES (%s, %s)", (req.domain_id, json.dumps(initial_policy)))
        conn.commit()
        policy_agent.refresh_policies() # Won't show in playground yet (inactive), which is correct
        return {"status": "success"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

# Note: The old '/admin/rule' endpoint is deprecated by the new Deploy workflow, 
# but kept here if needed for backward compatibility or direct API calls.
@app.post("/admin/rule")
def add_rule(req: NewRuleRequest):
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT policy_json FROM domain_policies WHERE domain_id = %s", (req.domain_id,))
        row = cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="Domain not found")
        
        policy = row[0]
        new_rule = {"entity_type": req.entity_type, "action": req.action, "config": req.config}
        if req.custom_regex: new_rule["custom_regex"] = req.custom_regex
        
        policy['rules'].append(new_rule)
        cur.execute("UPDATE domain_policies SET policy_json = %s WHERE domain_id = %s", (json.dumps(policy), req.domain_id))
        conn.commit()
        policy_agent.refresh_policies()
        return {"status": "success"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()