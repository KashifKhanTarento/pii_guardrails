# 📘 AI4I PII Guardrail (v0.3 Multi-Lingual & Context)

**Technical Handover & System Architecture Documentation**

## 1. Project Overview

The **AI4I PII Guardrail** is a microservice designed to act as a privacy firewall. It sits between client applications and downstream services, intercepting unstructured text to identify and redact Personally Identifiable Information (PII) in real-time.

**v3.0 Update Highlights:**
* **Dual-Engine Intelligence:** Seamlessly switches between **English** (`en_core_web_lg`) and **Hindi** (`xx_ent_wiki_sm`) based on request headers.
* **Context-Aware Strict Mode:** Implements a "User vs. Storage" logic. "User Mode" allows safe geographical terms (e.g., *Hoskote*) for chat utility, while "Storage Mode" forcibly redacts them for zero-trust compliance.
* **Smart Redaction:** Features email-aware masking (`j**@gmail.com`), phone hashing (HMAC), and demographic risk escalation (e.g., *Farmer* + *Location* = High Risk).
* **Live Orchestration Trace:** Continues to provide millisecond-accurate activity logs for "Fail-Closed" observability.

---

## 2. System Architecture

### 2.1 High-Level Component Diagram

The system now features a branching logic flow based on Language and Target context.

```mermaid
graph TD
    User[Client Application] -->|1. POST /redact| App[FastAPI Application]
    
    subgraph "Orchestration Core"
        App -->|Header: X-Language| LangSwitch{Language?}
        
        LangSwitch -->|en| Eng[English Engine<br/>Spacy Large]
        LangSwitch -->|hi| Hin[Hindi Engine<br/>Spacy Multi + Regex]
        
        Eng --> Anchors[Regex Anchors]
        Hin --> Anchors
        
        Anchors --> Context[AI Context Analysis]
        
        Context --> Strict{Strict Mode?}
        Strict -->|Yes| Block[Blocklist Scan<br/>Redact All Locs]
        Strict -->|No| Allow[Safety Check<br/>Allow Safe Locs]
        
        Block --> Redact[Smart Redaction]
        Allow --> Redact
    end
    
    subgraph "Data & Logs"
        App -->|Sync Policy| DB[(PostgreSQL 15)]
        Redact -->|Log Trace| DB
    end
    
    Redact -->|JSON + Trace| App
    App -->|Response| User

```

### 2.2 Key Directories

* `models/`: Stores local Spacy vectors (`en_core_web_lg`, `xx_ent_wiki_sm`) and optional LLM weights.
* `main.py`: Core logic containing the `DetectionEngine` (Dual-Language), `AuditLogger`, and API routes.
* `init.sql`: Database schema and seeded templates (including the new `demo_all` and `logistics_hindi`).
* `index.html`: Admin Console & Playground with "Waterfall" Trace UI.

---

## 3. Database Schema & Policies

### 3.1 Schema Design ("Clean Slate")

The system uses a **"Select-to-Deploy"** philosophy.

* **Table:** `domain_policies`
* **Default State:** `is_active = FALSE`.

| Column | Description |
| --- | --- |
| `domain_id` | Unique identifier (e.g., `demo_all`, `logistics_hindi`). |
| `policy_json` | JSON blob storing the active rule configuration. |
| `is_active` | Boolean flag. Controlled via the `/admin/deploy` endpoint. |

### 3.2 Available Templates (v3.0)

1. **`demo_all` (Super Domain):** Activates ALL capabilities (Credit Cards, Hindi, English, Email Masking).
2. **`logistics`:** Optimized for English addresses and phone numbers.
3. **`logistics_hindi`:** Specialized for Devanagari addresses (e.g., "टावर सी", "मकान नंबर").
4. **`finance`:** Banking focus (PAN, IFSC, Cards).

---

## 4. Logic & Algorithms

### 4.1 Dual-Engine Detection

* **English:** Uses a 500MB Large model for deep syntactic understanding of Western address formats.
* **Hindi:** Uses a lightweight Multi-lingual model combined with a **Custom Regex Layer** to handle alphanumerics (e.g., "Tower C") and agglutinative suffixes (e.g., "Me", "Par").

### 4.2 Strict Mode & Risk Escalation

* **Behavior:** Controlled via `X-Target` header.
* **User Mode:** Whitelists known "Safe Cities" to maintain conversation flow.
* **Storage Mode:** Inverts the logic—Safe Cities become a **Blocklist**.
* **Combination Risk:** If a Quasi-Identifier (e.g., "Farmer", "Doctor") is detected, the system automatically escalates "Safe" locations to "High Risk" to prevent re-identification (k-anonymity).

### 4.3 The "Trace Protocol"

The backend constructs a `trace` JSON array attached to every response, visualizing the decision path (e.g., "Why was 'Mysore' redacted? -> Strict Mode Blocklist").

---

## 5. Deployment Guide

### 5.1 Installation

1. **Clone & Setup**:
```bash
git clone <repo_url>
cd PII_G

```


2. **Build & Run (Auto-Provisioning)**:
The Dockerfile now handles multi-language model downloads automatically.
```bash
docker-compose up --build

```



### 5.2 Resetting the Database

To wipe old policies and load the new `demo_all` and Hindi templates:

```bash
docker-compose down
docker volume rm pii_g_postgres_data
docker-compose up --build -d

```

---

## 6. API Documentation

### 6.1 Core Endpoint: `/redact`

**Headers:**

* `X-Language`: `en` (default) or `hi`.
* `X-Target`: `user` (allow safe terms) or `storage` (strict redaction).

**Request:**

```json
{
  "text": "My name is Rahul. I live in Tower C, Meadows.",
  "domain": "demo_all"
}

```

**Response:**

```json
{
  "redacted_text": "My name is [NAME]. I live in [HOUSE], [LOC].",
  "trace": [
    {
      "step": "Anchors (en)",
      "status": "Success",
      "details": "Found 1 high-risk anchors."
    },
    {
      "step": "AI & Context (en)",
      "status": "Success",
      "details": "Applied actions to 2 segments."
    }
  ],
  "metadata": { "language": "en", "processing_time_ms": 12 }
}

```

### 6.2 Admin Endpoints

* `POST /admin/deploy`: Activates a domain template.
* `POST /admin/activate-domains`: Bulk activation for testing.
* `POST /admin/generate-regex`: AI-assisted regex generation.

---

## 7. Frontend Features

1. **Playground:** Now supports toggling **Language** and **Enforcement Target** (Strict/User) directly from the UI.
2. **Trace Panel:** Visualizes the specific engine (Hindi/English) used for the request.
3. **Policy Manager:** deploying `demo_all` instantly enables a full-spectrum test environment.

---

## 8. Troubleshooting

| Issue | Solution |
| --- | --- |
| **Hindi text not redacted** | Ensure `X-Language: hi` header is sent. Verify `logistics_hindi` or `demo_all` domain is active. |
| **"Safe" city redacted** | Check if `X-Target` is set to `storage`. Switch to `user` to allow safe terms. |
| **False Positives** | The `demo_all` domain is aggressive. For production, use a specific domain like `logistics`. |

```

```