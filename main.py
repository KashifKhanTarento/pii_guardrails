from fastapi import FastAPI, HTTPException, Request, Header
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
import psycopg2
from psycopg2.extras import RealDictCursor
import spacy
from llama_cpp import Llama 

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
        cur.execute("SELECT domain_id, policy_json FROM domain_policies WHERE is_active = TRUE;")
        rows = cur.fetchall()
        self._cache = {row['domain_id']: row['policy_json'] for row in rows}
        conn.close()

    def get_policy(self, domain: str):
        return self._cache.get(domain)
    
    def list_domains(self):
        return list(self._cache.keys())

policy_agent = PolicySyncAgent()

# --- 2. DETECTION ENGINE (HYBRID v0.2.1) ---
class DetectedEntity(BaseModel):
    entity_type: str
    start_index: int
    end_index: int
    text_segment: str
    detection_source: str

class DetectionEngine:
    # [LAYER 1] Static Anchors & Regex
    STATIC_PATTERNS = {
        "AADHAAR_UID": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        "PAN_CARD": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
        "PIN_CODE": re.compile(r"\b\d{3}\s?\d{3}\b"),
        "PHONE": re.compile(r"\b(\+91[\-\s]?)?[6-9]\d{9}\b"),
        # Catches "No. 32", "Flat 404", "#12"
        "HOUSE_NUMBER": re.compile(r"\b(No\.|Flat|House|H\.No|Door|#)\s?[\w\-/]+\b", re.IGNORECASE) 
    }

    # [LAYER 2] The Suffix Scout (Language Agnostic)
    # Full list restored
    INDIAN_ADDRESS_SUFFIXES = [
        # English/Universal
        "Road", "Street", "St", "Ave", "Lane", "Cross", "Main", "Block", "Layout", 
        "Nagar", "Poor", "Pur", "Pura", "Bad", "Colony", "Enclave", "Apartment", "Apt", 
        "Heights", "Villa", "Residency", "Park", "Gate", "Phase", "Sector",
        # Hindi/Urdu
        "Manzil", "Niwas", "Bhavan", "Nilaya", "Kuteer", "Marg", "Chowk", "Vihar",
        # Kannada/South
        "Mane", "Halli", "Palaya", "Sandra", "Gutta", "Kere", "District", "Town", "Mandal"
    ]

    def __init__(self):
        print("🧠 Loading NLP Model...")
        try:
            self.nlp = spacy.load("en_core_web_lg")
            print("✅ NLP Model Loaded.")
        except Exception as e:
            print(f"❌ Failed to load NLP Model: {e}")
            self.nlp = None

    def detect(self, text: str, rules: List[Dict], trace_log: List):
        detected = []
        active_types = [r['entity_type'] for r in rules]
        
        # --- PHASE 1: Regex Anchors (The Scout) ---
        t0 = time.time()
        regex_count = 0
        
        # 1a. Run configured rules (Custom + Static)
        for rule in rules:
            e_type = rule['entity_type']
            pattern = None
            source_label = "REGEX: Static"
            
            # Robust Error Handling restored
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
                    regex_count += 1
                    detected.append(DetectedEntity(
                        entity_type=e_type, 
                        start_index=match.start(), 
                        end_index=match.end(), 
                        text_segment=match.group(),
                        detection_source=source_label
                    ))

        # 1b. Run Hidden Anchors (House Numbers/PIN) if Location is active
        is_location_active = any(x in active_types for x in ["LOCATION", "ADDRESS", "GPE"])
        if is_location_active:
            for anchor_type in ["HOUSE_NUMBER", "PIN_CODE"]:
                pattern = self.STATIC_PATTERNS[anchor_type]
                for match in pattern.finditer(text):
                    detected.append(DetectedEntity(
                        entity_type="LOCATION", 
                        start_index=match.start(),
                        end_index=match.end(),
                        text_segment=match.group(),
                        detection_source=f"ANCHOR: {anchor_type}"
                    ))

        # --- PHASE 2: Suffix Heuristics (The Scholar) ---
        if is_location_active:
            words = text.split()
            cursor = 0
            for i, word in enumerate(words):
                clean_word = re.sub(r'[^\w]', '', word)
                if clean_word in self.INDIAN_ADDRESS_SUFFIXES and i > 0:
                    prev_word = words[i-1]
                    if prev_word and prev_word[0].isupper():
                        # Found "Gokul Mane" -> Redact both
                        start = text.find(prev_word, cursor)
                        if start != -1:
                            end = text.find(word, start) + len(word)
                            detected.append(DetectedEntity(
                                entity_type="LOCATION",
                                start_index=start,
                                end_index=end,
                                text_segment=text[start:end],
                                detection_source=f"SUFFIX: {clean_word}"
                            ))
                cursor += len(word) + 1

        trace_log.append({
            "step": "Static & Heuristic", 
            "status": "Success", 
            "time_ms": int((time.time()-t0)*1000),
            "details": f"Ran anchors & suffix scan. Found {len(detected)} items."
        })

        # --- PHASE 3: AI Context (The Attention) ---
        t1 = time.time()
        
        # [RESTORED] Full Enterprise Mappings
        AI_MAPPINGS = {
            "PERSON": ["PERSON", "NAME", "STUDENT", "CLIENT", "PATIENT", "EMPLOYEE", "SUSPECT", "VICTIM"],
            "GPE": ["LOCATION", "CITY", "COUNTRY", "STATE", "PLACE", "ORIGIN", "DESTINATION", "ADDRESS"],
            "FAC": ["LOCATION", "BUILDING", "LANDMARK", "APARTMENT", "SOCIETY"], 
            "LOC": ["LOCATION", "STREET", "AREA", "ADDRESS"], 
            "ORG": ["ORG", "COMPANY", "BANK", "HOSPITAL", "AGENCY", "FIRM"]
        }

        # Optimization: Only run AI if relevant rules are active
        all_keywords = [kw for valid_list in AI_MAPPINGS.values() for kw in valid_list]
        needs_ai = any(kw in rule_name.upper() for rule_name in active_types for kw in all_keywords)
        
        ai_count = 0
        if self.nlp and needs_ai:
            doc = self.nlp(text)
            for ent in doc.ents:
                mapped_type = None
                if ent.label_ in active_types:
                    mapped_type = ent.label_
                elif ent.label_ in AI_MAPPINGS:
                    potential_keywords = AI_MAPPINGS[ent.label_]
                    for rule_name in active_types:
                        if any(kw in rule_name.upper() for kw in potential_keywords):
                            mapped_type = rule_name
                            break
                
                if mapped_type:
                    ai_count += 1
                    detected.append(DetectedEntity(
                        entity_type=mapped_type,
                        start_index=ent.start_char,
                        end_index=ent.end_char,
                        text_segment=ent.text,
                        detection_source=f"AI: NER Model ({ent.label_} -> {mapped_type})"
                    ))
        
        trace_log.append({
            "step": "AI Context Engine", 
            "status": "Success" if self.nlp else "Skipped", 
            "time_ms": int((time.time()-t1)*1000),
            "details": f"Spacy Large Model invoked. Mapped {ai_count} entities."
        })

        # --- PHASE 4: Geometric Glue (The Bridge) ---
        if is_location_active:
            before_count = len(detected)
            
            # Step A: Run the Glue (Bridge two islands)
            detected = self.apply_greedy_glue(detected, text)
            
            # [NEW] Step B: Run the Domino (Extend one island)
            detected = self.apply_domino_effect(detected, text)
            
            if len(detected) != before_count:
                trace_log.append({
                    "step": "Geometric Glue & Domino", 
                    "status": "Applied", 
                    "time_ms": 1, 
                    "details": "Merged clusters and extended chains (Address logic)"
                })

        return detected

    def apply_greedy_glue(self, entities: List[DetectedEntity], text: str) -> List[DetectedEntity]:
        if not entities: return []
        
        loc_entities = [e for e in entities if e.entity_type in ["LOCATION", "ADDRESS", "GPE", "FAC", "LOC"]]
        other_entities = [e for e in entities if e not in loc_entities]
        
        if not loc_entities: return entities

        # Sort by position
        sorted_ents = sorted(loc_entities, key=lambda x: x.start_index)
        merged = []
        
        current = sorted_ents[0]
        
        for next_ent in sorted_ents[1:]:
            # DISTANCE THRESHOLD: 40 characters (approx 6-8 words)
            gap = next_ent.start_index - current.end_index
            
            if gap < 40 and gap > 0: 
                gap_text = text[current.end_index : next_ent.start_index]
                # Heuristic: If gap has <= 5 words, assume it's part of the address
                if len(gap_text.split()) <= 5: 
                    current = DetectedEntity(
                        entity_type="LOCATION", 
                        start_index=current.start_index,
                        end_index=next_ent.end_index,
                        text_segment=text[current.start_index : next_ent.end_index],
                        detection_source="GEOMETRY: Proximity Bridge"
                    )
                else:
                    merged.append(current)
                    current = next_ent
            else:
                merged.append(current)
                current = next_ent
        
        merged.append(current)
        return merged + other_entities

    def apply_domino_effect(self, entities: List[DetectedEntity], text: str) -> List[DetectedEntity]:
        # [NEW LOGIC] Fixes "Madanapalli, Chittoor" by chaining location islands
        loc_entities = [e for e in entities if e.entity_type in ["LOCATION", "ADDRESS", "GPE"]]
        if not loc_entities: return entities
        
        new_additions = []
        
        for ent in loc_entities:
            # Look ahead in the text from the end of the current entity
            cursor = ent.end_index
            
            # Loop to catch chains like "City, District, State"
            while cursor < len(text):
                # Regex: Look for comma/space followed immediately by a Proper Noun
                # matches: ", Chittoor" or " Chittoor"
                match = re.match(r'^\s*(,|and)?\s*([A-Z][a-z]+)', text[cursor:])
                
                if match:
                    word = match.group(2)
                    # Safety Check: Don't redact common verbs/words if they accidentally get capitalized
                    if word.lower() in ["and", "but", "the", "is", "at", "in"]: 
                        break
                        
                    # Create new entity for the extension
                    full_match_len = len(match.group(0))
                    new_ent = DetectedEntity(
                        entity_type="LOCATION",
                        start_index=cursor,
                        end_index=cursor + full_match_len,
                        text_segment=match.group(0),
                        detection_source="GEOMETRY: Domino Extension"
                    )
                    new_additions.append(new_ent)
                    
                    # Advance cursor to keep looking for the NEXT part of the chain
                    cursor += full_match_len
                else:
                    break # Chain broken
        
        return entities + new_additions

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
def redact_text(request: RedactionRequest, x_tenant_id: str = Header(None)):
    global_start = time.time()
    trace = [] # Initialize trace immediately for safety
    
    # STEP 1: Authorization
    trace.append({
        "step": "Request Authorization",
        "status": "Success",
        "time_ms": 1,
        "details": f"Tenant ID: {x_tenant_id or 'Anonymous'}. Engine v0.2.1 Hybrid."
    })

    policy = policy_agent.get_policy(request.domain)
    if not policy:
        trace.append({"step": "Policy Retrieval", "status": "Failed", "time_ms": 0, "details": "Domain not active."})
        raise HTTPException(status_code=400, detail="Invalid or Inactive Domain")
    
    try:
        # STEP 2: Detection
        entities = detection_engine.detect(request.text, policy['rules'], trace)
        
        # STEP 3: Redaction Execution
        t_redact = time.time()
        redacted_text = request.text
        
        for entity in sorted(entities, key=lambda x: x.start_index, reverse=True):
            rule = next((r for r in policy['rules'] if r['entity_type'] == entity.entity_type), None)
            
            # Fallback: If "Geometric Bridge" created a generic LOCATION, use any available Location rule
            if not rule and entity.entity_type == "LOCATION":
                 rule = next((r for r in policy['rules'] if r['entity_type'] in ["LOCATION", "GPE", "ADDRESS"]), None)
            
            if not rule: continue

            replacement = "[REDACTED]"
            if rule['action'] == "REDACT_TAG":
                replacement = rule['config'].get('tag_label', f'[{entity.entity_type}]')
            elif rule['action'] == "MASK":
                visible = rule['config'].get('visible_suffix_length', 0)
                raw = entity.text_segment
                if visible > 0 and len(raw) > visible:
                    replacement = "X" * (len(raw) - visible) + raw[-visible:]
                else:
                    replacement = "X" * len(raw)
            elif rule['action'] == "HASH":
                replacement = hmac.new(b"secret", entity.text_segment.encode(), hashlib.sha256).hexdigest()[:10] + "..."

            # Apply replacement
            redacted_text = redacted_text[:entity.start_index] + replacement + redacted_text[entity.end_index:]
        
        trace.append({
            "step": "Policy Enforcement",
            "status": "Success",
            "time_ms": int((time.time() - t_redact) * 1000),
            "details": f"Applied actions to {len(entities)} detected segments."
        })

        processing_time_ms = int((time.time() - global_start) * 1000)

        return {
            "original_text": request.text, 
            "redacted_text": redacted_text, 
            "pii_detected": entities,
            "trace": trace,
            "metadata": {
                "processing_time_ms": processing_time_ms,
                "tenant_id": x_tenant_id,
                "engine_version": "v0.2.1 Hybrid"
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

# --- ADMIN ENDPOINTS ---

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
    # Only SAVES the rules. Does NOT enforce activation.
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT policy_json FROM domain_policies WHERE domain_id = %s", (req.domain_id,))
        row = cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="Domain not found")
        
        current_policy = row[0]
        current_policy['rules'] = req.rules
        
        cur.execute("UPDATE domain_policies SET policy_json = %s WHERE domain_id = %s", 
                    (json.dumps(current_policy), req.domain_id))
        conn.commit()
        return {"status": "saved", "active_rules_count": len(req.rules)}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/admin/activate-domains")
def bulk_activate(req: BulkActivateRequest):
    # The "Apply" Logic
    conn = policy_agent.get_db_connection()
    cur = conn.cursor()
    try:
        # 1. Reset ALL to False
        cur.execute("UPDATE domain_policies SET is_active = FALSE")
        
        # 2. Activate ONLY the selected ones
        if req.domain_ids:
            cur.execute("UPDATE domain_policies SET is_active = TRUE WHERE domain_id = ANY(%s)", (req.domain_ids,))
            
        conn.commit()
        
        # 3. Refresh Cache immediately
        policy_agent.refresh_policies()
        return {"status": "success", "active_count": len(req.domain_ids)}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

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
        except re.error: raise HTTPException(status_code=500, detail="Generated pattern was invalid.")
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
    finally:
        conn.close()