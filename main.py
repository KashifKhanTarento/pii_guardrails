from fastapi import FastAPI, HTTPException, Request, Header, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re
import hashlib
import hmac
import os
import json
import time
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
import spacy

# --- CONFIGURATION ---
app = FastAPI()
DB_HOST = os.getenv("DB_HOST", "localhost") 
DB_NAME = os.getenv("DB_NAME", "pii_guardrail")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "secret")

# --- 1. KNOWLEDGE BASE LOADER ---
class KnowledgeBase:
    def __init__(self):
        self.patterns = {}
        self.suffixes = {}
        self.safe_geo = {}
        self.connected = False

    def get_db_connection(self):
        return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

    def refresh(self):
        for attempt in range(1, 11):
            try:
                print(f"🔄 KnowledgeBase Load Attempt {attempt}...")
                conn = self.get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # 1. Patterns
                cur.execute("SELECT entity_label, lang_code, regex_pattern FROM pattern_library WHERE is_active = TRUE")
                for row in cur.fetchall():
                    lang, label = row['lang_code'], row['entity_label']
                    langs = ['en', 'hi', 'mr', 'ta'] if lang == 'all' else [lang]
                    for l in langs:
                        if l not in self.patterns: self.patterns[l] = {}
                        try: self.patterns[l][label] = re.compile(row['regex_pattern'], re.UNICODE | re.IGNORECASE)
                        except: pass

                # 2. Geo Terms
                cur.execute("SELECT term_text, lang_code, term_type FROM geo_library WHERE is_active = TRUE")
                for row in cur.fetchall():
                    lang, term, typ = row['lang_code'], row['term_text'], row['term_type']
                    if typ == 'SUFFIX':
                        if lang not in self.suffixes: self.suffixes[lang] = []
                        self.suffixes[lang].append(term)
                    elif typ == 'SAFE_CITY':
                        if lang not in self.safe_geo: self.safe_geo[lang] = set()
                        self.safe_geo[lang].add(term.lower())
                
                conn.close()
                self.connected = True
                print(f"✅ Knowledge Base Loaded! (Suffixes: {len(self.suffixes.get('en', []))})")
                return
            except Exception as e:
                print(f"⚠️ KB Load Failed ({e}). Retrying in 3s...")
                time.sleep(3)
        print("❌ CRITICAL: Could not load KnowledgeBase after 10 attempts.")

KB = KnowledgeBase()

# --- 2. DETECTION ENGINE (FULL FEATURES) ---
class DetectedEntity(BaseModel):
    entity_type: str
    start_index: int
    end_index: int
    text_segment: str
    detection_source: str
    risk_score: float = 0.0

class DetectionEngine:
    # Stop words for backward expansion
    STOP_WORDS = {
        'en': {'is', 'are', 'am', 'was', 'were', 'my', 'our', 'the', 'a', 'an', 'at', 'in', 'on', 'to', 'from', 'addr', 'address', 'lives', 'living', 'stay', 'staying'},
        'hi': {'है', 'हूँ', 'हो', 'था', 'थे', 'मेरा', 'मेरी', 'मेरे', 'का', 'की', 'के', 'में', 'पर', 'से', 'पता', 'रहता'},
        'mr': {'आहे', 'होता', 'होते', 'माझा', 'माझी', 'माझे', 'चा', 'ची', 'चे', 'मध्ये', 'वर', 'ून', 'पत्ता', 'राहतो'},
        'ta': {'உள்ளது', 'இருக்கிறது', 'எனது', 'என்', 'முகவரி', 'இல்', 'இடத்தில்', 'வசிப்பவர்', 'எண்'}
    }

    # Blocklist to prevent "Phone" being detected as Name
    FALSE_POSITIVES = {
        "फ़ोन", "मोबाइल", "ईमेल", "पता", "नंबर", 
        "phone", "mobile", "email", "address", "number",
        "தொலைபேசி", "முகவரி", 
        "फोन", "मोबाईल", "पत्ता"
    }

    # Context Connectors for Chain Logic
    CONNECTORS = {
        "en": {"pre": ["at", "in", "on", "near"], "post": []},
        "hi": {"pre": [], "post": ["में", "पर", "के पास", "स्थित"]},
        "mr": {"pre": [], "post": ["मध्ये", "वर", "जवळ", "समोर"]},
        "ta": {"pre": [], "post": ["இல்", "இடம்", "அருகில்"]} 
    }
    
    # Quasi-Identifiers (Risk Escalation)
    COMMON_OCCUPATIONS = {
        "farmer", "driver", "teacher", "engineer", "doctor", "nurse", "worker", 
        "laborer", "coolie", "maid", "guard", "police", "soldier", "clerk", "officer"
    }
    GENDER_TERMS = {"male", "female", "man", "woman", "boy", "girl", "transgender"}

    def __init__(self):
        print("🧠 Loading NLP Models...")
        try:
            self.nlp_en = spacy.load("en_core_web_lg", disable=["parser", "tagger"])
            self.nlp_multi = spacy.load("xx_ent_wiki_sm")
            print("✅ Models Ready.")
        except:
            self.nlp_en = None; self.nlp_multi = None

    def is_boundary(self, char):
        return not char.isalnum() and char != '_'

    def expand_context_left(self, text: str, start_index: int, lang: str) -> int:
        if start_index == 0: return 0
        preceding_text = text[:start_index]
        tokens = list(re.finditer(r'\S+', preceding_text))
        if not tokens: return start_index

        new_start = start_index
        stops = self.STOP_WORDS.get(lang, self.STOP_WORDS['en'])
        
        for match in reversed(tokens):
            word_clean = match.group().strip(',.-:').lower()
            if word_clean in stops: break
            new_start = match.start()
        return new_start

    def detect_quasi_identifiers(self, text: str, lang: str = "en") -> List[DetectedEntity]:
        quasi_ents = []
        words = re.findall(r'\b\w+\b', text.lower())
        for w in words:
            if w in self.COMMON_OCCUPATIONS:
                 for m in re.finditer(rf"\b{w}\b", text, re.IGNORECASE):
                     quasi_ents.append(DetectedEntity(entity_type="OCCUPATION", start_index=m.start(), end_index=m.end(), text_segment=m.group(), detection_source="KEYWORD", risk_score=0.3))
            if w in self.GENDER_TERMS:
                 for m in re.finditer(rf"\b{w}\b", text, re.IGNORECASE):
                     quasi_ents.append(DetectedEntity(entity_type="GENDER", start_index=m.start(), end_index=m.end(), text_segment=m.group(), detection_source="KEYWORD", risk_score=0.2))
        return quasi_ents

    def apply_specificity_chain(self, anchors, candidates, text, lang):
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
                    gap_start = min(current.end_index, neighbor.end_index)
                    gap_end = max(current.start_index, neighbor.start_index)
                    gap_text = text[gap_start:gap_end]
                    
                    has_conn = any(c in gap_text for c in connectors['pre'] + connectors['post'])
                    if (len(gap_text) < 25) or has_conn:
                        current.risk_score = 1.0 
                        current.detection_source = "CHAIN: Extended"
                        final_set.append(current)
                        break 
        return final_set

    def detect(self, text: str, rules: List[Dict], trace_log: List, strict_mode: bool = False, lang: str = "en"):
        detected = []
        t0 = time.time()
        
        if not KB.connected: KB.refresh()

        patterns = KB.patterns.get(lang, {})
        suffixes = KB.suffixes.get(lang, [])
        safe_geo = KB.safe_geo.get(lang, set())
        
        active_types = [r['entity_type'] for r in rules]
        is_loc_active = any(x in active_types for x in ["LOCATION", "ADDRESS", "HOUSE_ANCHOR"])

        # PHASE 1: AI MODEL
        nlp = self.nlp_en if lang == 'en' else self.nlp_multi
        ai_candidates = []
        ai_count = 0
        if nlp:
            doc = nlp(text)
            for ent in doc.ents:
                # Blacklist Check
                if ent.text.lower() in self.FALSE_POSITIVES: continue
                
                mapped = "LOCATION" if ent.label_ in ["GPE", "LOC", "FAC", "ORG"] else ent.label_
                if ent.label_ == "PERSON": mapped = "PERSON"
                
                if mapped == "LOCATION" and is_loc_active:
                    # In strict mode, redact everything. In user mode, allow safe cities.
                    detected.append(DetectedEntity(entity_type="LOCATION", start_index=ent.start_char, end_index=ent.end_char, text_segment=ent.text, detection_source=f"AI: Strict", risk_score=1.0 if strict_mode else (0.1 if ent.text.lower() in safe_geo else 1.0)))
                    ai_count += 1
                elif mapped in active_types:
                    detected.append(DetectedEntity(entity_type=mapped, start_index=ent.start_char, end_index=ent.end_char, text_segment=ent.text, detection_source=f"AI: {ent.label_}", risk_score=1.0))
                    ai_count += 1
        
        trace_log.append({"step": "AI Extraction", "status": "Success", "details": f"AI identified {ai_count} entities."})

        # PHASE 1.5: DICTIONARY MATCH (Strict Mode Only)
        # Catches cities like "Bangalore" if AI misses them
        dict_count = 0
        if is_loc_active and strict_mode:
            for city in safe_geo:
                for m in re.finditer(r'(?<!\w)' + re.escape(city) + r'(?!\w)', text, re.IGNORECASE):
                    detected.append(DetectedEntity(entity_type="LOCATION", start_index=m.start(), end_index=m.end(), text_segment=m.group(), detection_source="DICT", risk_score=1.0))
                    dict_count += 1
        
        if strict_mode:
             trace_log.append({"step": "Dictionary Scan", "status": "Success", "details": f"Found {dict_count} cities via Dictionary."})

        # PHASE 2: SUFFIX SCANNING (SCRIPT-AWARE)
        suffix_count = 0
        if is_loc_active and suffixes:
            for s in suffixes:
                start = 0
                while True:
                    idx = text.find(s, start)
                    if idx == -1: break
                    
                    # English needs strict word boundaries; Indic is looser due to agglutination
                    if lang == 'en' and not (self.is_boundary(text[idx-1]) if idx>0 else True): 
                        start = idx + 1; continue
                    
                    new_start = self.expand_context_left(text, idx, lang)
                    detected.append(DetectedEntity(entity_type="LOCATION", start_index=new_start, end_index=idx+len(s), text_segment=text[new_start:idx+len(s)], detection_source=f"SUFFIX: {s}", risk_score=1.0))
                    suffix_count += 1
                    
                    start = idx + 1
        
        trace_log.append({"step": "Context Scan", "status": "Success", "details": f"Found {suffix_count} anchors via suffixes."})

        # PHASE 3: REGEX
        regex_count = 0
        for rule in rules:
            if "custom_regex" in rule and rule['custom_regex']:
                try:
                    for m in re.finditer(rule['custom_regex'], text, re.UNICODE | re.IGNORECASE):
                        detected.append(DetectedEntity(entity_type=rule['entity_type'], start_index=m.start(), end_index=m.end(), text_segment=m.group(), detection_source="REGEX: Custom", risk_score=1.0))
                        regex_count += 1
                except: pass
            
            lbl = rule['entity_type']
            if lbl in patterns and not rule.get('custom_regex'):
                for match in patterns[lbl].finditer(text):
                     if match.group().lower() in self.FALSE_POSITIVES: continue
                     detected.append(DetectedEntity(entity_type=lbl, start_index=match.start(), end_index=match.end(), text_segment=match.group(), detection_source=f"REGEX: {lbl}", risk_score=1.0))
                     regex_count += 1
        
        trace_log.append({"step": "Regex Layer", "status": "Success", "details": f"Matched {regex_count} patterns."})

        # PHASE 4: RISK & CHAIN LOGIC
        quasi_ents = self.detect_quasi_identifiers(text, lang)
        detected.extend(quasi_ents)
        if quasi_ents and ai_candidates and not strict_mode:
            for c in ai_candidates:
                c.risk_score = 1.0
                c.detection_source = "RISK: Escalated"
                detected.append(c)
            ai_candidates = []

        if is_loc_active:
            detected = self.apply_specificity_chain(detected, ai_candidates, text, lang)

        if strict_mode:
             for c in ai_candidates: 
                 c.risk_score = 1.0
                 detected.append(c)

        trace_log.append({"step": "Risk Assessment", "status": "Success", "time_ms": int((time.time()-t0)*1000), "details": f"Final Entity Count: {len(detected)}"})
        return detected

detection_engine = DetectionEngine()

# --- 3. API & POLICY AGENT ---
class PolicySyncAgent:
    def __init__(self):
        self._cache = {}
        self.connected = False
    
    def refresh_policies(self):
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT domain_id, policy_json FROM domain_policies WHERE is_active = TRUE")
            self._cache = {row['domain_id']: row['policy_json'] for row in cur.fetchall()}
            conn.close()
            self.connected = True
            print("✅ Policies Loaded.")
        except: time.sleep(3)

    def get_policy(self, domain): 
        if not self.connected: self.refresh_policies()
        return self._cache.get(domain)
    
    def list_domains(self): 
        if not self.connected: self.refresh_policies()
        return list(self._cache.keys())

policy_agent = PolicySyncAgent()

class AuditLogger:
    def log_event(self, trace_id, tenant_id, domain, target, pii_count, processing_ms, trace):
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
            cur = conn.cursor()
            cur.execute("INSERT INTO audit_logs (trace_id, tenant_id, domain_id, target_context, pii_count, processing_ms, trace_json) VALUES (%s, %s, %s, %s, %s, %s, %s)", (trace_id, tenant_id, domain, target, pii_count, processing_ms, json.dumps(trace)))
            conn.commit(); conn.close()
        except: pass
audit_logger = AuditLogger()

class RedactionRequest(BaseModel): text: str; domain: str
class DeployRequest(BaseModel): domain_id: str; rules: List[Dict]
class BulkActivateRequest(BaseModel): domain_ids: List[str]
class GenerateRegexRequest(BaseModel): example_text: str
class NewDomainRequest(BaseModel): domain_id: str; description: str

@app.on_event("startup")
async def startup_event():
    print("🚀 System Startup: Initializing DB Connections...")
    KB.refresh()
    policy_agent.refresh_policies()

@app.get("/")
def read_root(): return HTMLResponse(open("index.html").read())
@app.get("/domains")
def get_domains(): return policy_agent.list_domains()
@app.get("/policy/{domain}")
def get_policy(domain: str): return policy_agent.get_policy(domain) or {}

@app.post("/redact")
def redact_text(request: RedactionRequest, background_tasks: BackgroundTasks, x_tenant_id: str = Header(None), x_target: str = Header("user"), x_language: str = Header("en")):
    start = time.time(); trace_id = str(uuid.uuid4()); trace = []
    trace.append({"step": "Request", "status": "Success", "details": f"Target: {x_target}, Lang: {x_language}"})
    policy = policy_agent.get_policy(request.domain)
    if not policy: raise HTTPException(400, "Invalid Domain")
    is_strict = (x_target.lower() != "user")
    
    try:
        entities = detection_engine.detect(request.text, policy['rules'], trace, is_strict, x_language)
        
        entities.sort(key=lambda x: x.start_index)
        unique = []
        if entities:
            curr = entities[0]
            for next_ent in entities[1:]:
                if next_ent.start_index < curr.end_index:
                    new_end = max(curr.end_index, next_ent.end_index)
                    curr.end_index = new_end
                    curr.text_segment = request.text[curr.start_index:new_end]
                    curr.risk_score = max(curr.risk_score, next_ent.risk_score)
                else: unique.append(curr); curr = next_ent
            unique.append(curr)

        redacted = request.text
        for ent in sorted(unique, key=lambda x: x.start_index, reverse=True):
            rule = next((r for r in policy['rules'] if r['entity_type'] == ent.entity_type), None)
            if not rule and ent.entity_type == "LOCATION":
                 rule = next((r for r in policy['rules'] if r['entity_type'] in ["LOCATION", "GPE", "ADDRESS"]), None)
            if not rule and ent.entity_type == "PERSON":
                 rule = next((r for r in policy['rules'] if r['entity_type'] in ["PERSON", "NAME"]), None)
            if not rule: continue

            rep = "[REDACTED]"
            if rule['action'] == "REDACT_TAG": rep = rule['config'].get('tag_label', f'[{ent.entity_type}]')
            elif rule['action'] == "HASH": rep = hmac.new(b"secret", ent.text_segment.encode(), hashlib.sha256).hexdigest()[:10] + "..."
            elif rule['action'] == "MASK":
                char = rule['config'].get('mask_char', 'X')
                if ent.entity_type == "EMAIL" and "@" in ent.text_segment:
                     try:
                        l, d = ent.text_segment.split('@', 1)
                        rep = (l[:3] + char*(len(l)-3) if len(l)>3 else char*len(l)) + "@" + d
                     except: rep = char*len(ent.text_segment)
                else: rep = char * len(ent.text_segment)

            redacted = redacted[:ent.start_index] + rep + redacted[ent.end_index:]

        ms = int((time.time() - start) * 1000)
        background_tasks.add_task(audit_logger.log_event, trace_id, x_tenant_id, request.domain, x_target, len(unique), ms, trace)
        return {"original_text": request.text, "redacted_text": redacted, "pii_detected": unique, "trace": trace, "metadata": {"processing_time_ms": ms, "language": x_language}}
    except Exception as e:
        print(f"FAIL: {e}"); raise HTTPException(500, str(e))

# Admin endpoints (Simplified)
@app.get("/admin/all-domains")
def get_all_domains():
    conn = KB.get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT domain_id, is_active, policy_json->'meta'->>'description' as description FROM domain_policies ORDER BY domain_id;")
    rows = cur.fetchall(); conn.close(); return rows
@app.post("/admin/deploy")
def deploy(req: DeployRequest):
    conn = KB.get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT policy_json FROM domain_policies WHERE domain_id = %s", (req.domain_id,))
    row = cur.fetchone(); p = row[0]; p['rules'] = req.rules
    cur.execute("UPDATE domain_policies SET policy_json = %s WHERE domain_id = %s", (json.dumps(p), req.domain_id))
    conn.commit(); conn.close(); policy_agent.refresh_policies(); return {"status": "saved"}
@app.post("/admin/activate-domains")
def activate(req: BulkActivateRequest):
    conn = KB.get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE domain_policies SET is_active = FALSE")
    if req.domain_ids: cur.execute("UPDATE domain_policies SET is_active = TRUE WHERE domain_id = ANY(%s)", (req.domain_ids,))
    conn.commit(); conn.close(); policy_agent.refresh_policies(); return {"status": "success"}
@app.post("/admin/generate-regex")
def gen_regex(req: GenerateRegexRequest): return {"regex": r"\b" + re.escape(req.example_text) + r"\b"} 
@app.post("/admin/domain")
def create_domain(req: NewDomainRequest):
    conn = KB.get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO domain_policies VALUES (%s, FALSE, %s)", (req.domain_id, json.dumps({"meta":{"version":"1.0"},"rules":[]})))
    conn.commit(); conn.close(); return {"status": "success"}