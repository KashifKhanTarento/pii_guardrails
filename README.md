# 📘 AI4I PII Guardrail (v2.1 Enterprise)

**Technical Handover & System Architecture Documentation**

## 1. Project Overview

The **AI4I PII Guardrail** is a microservice designed to act as a privacy firewall. It sits between client applications and downstream services (like LLMs or Databases), intercepting unstructured text to identify and redact Personally Identifiable Information (PII) in real-time.

**Key Design Principles:**

* **Fail-Closed Security:** If the detection engine or AI model fails, the system blocks the request (HTTP 500) rather than leaking data.
* **Hybrid Detection:** Uses high-speed Deterministic Regex for pattern matching and Local AI (NER) for contextual entity recognition.
* **Privacy-First:** Fully air-gapped capability. No data leaves the container environment.
* **Config-Driven:** Policy rules are stored in a PostgreSQL database, allowing dynamic updates without restarting the application.

---

## 2. System Architecture

### 2.1 High-Level Component Diagram

The system is containerized using Docker Compose and consists of three primary services running inside a WSL 2 environment.

```mermaid
graph TD
    User[Client Application / User] -->|1. POST /redact| App[FastAPI Application (Port 8000)]
    
    subgraph "Docker Network (pii_guardrail_net)"
        App -->|2. Fetch Policy| DB[(PostgreSQL 15)]
        
        subgraph "Redaction Core"
            App -->|3a. Structural Analysis| PyLogic[Deterministic Regex Builder]
            App -->|3b. Context Check| Spacy[Spacy NER Model]
            App -->|3c. Admin Config| Llama[Llama-3.2-3B (Local LLM)]
        end
    end
    
    App -->|4. Return Sanitized JSON| User

```

### 2.2 Directory Structure

```text
PII_G/
├── models/
│   └── llama-3.2-3b-instruct.Q4_K_M.gguf  # [CRITICAL] Local AI Model File (~2.4GB)
├── main.py                                # FastAPI Backend & Logic Core
├── init.sql                               # Database Schema & Seed Data (6 Domains)
├── index.html                             # Single-Page Frontend (Playground + Admin)
├── requirements.txt                       # Python Dependencies
├── Dockerfile                             # App Container Config
└── docker-compose.yml                     # Orchestration Config

```

---

## 3. Database Schema & Policies

### 3.1 Schema Design

The system uses a flexible schema to allow for "Hot-Swappable" policies.

* **Table:** `domain_policies`
* **Primary Key:** `domain_id` (e.g., 'finance', 'healthcare')

| Column | Type | Description |
| --- | --- | --- |
| `domain_id` | `VARCHAR(50)` | Unique identifier for the regulatory scope. |
| `policy_json` | `JSONB` | Stores the active rules, regex patterns, and redaction configs. |
| `is_active` | `BOOLEAN` | Hard switch to disable a domain instantly. |

### 3.2 Supported Domains (Pre-Seeded)

The `init.sql` script pre-loads the following domains based on the specification:

1. **Education**: `STUDENT_ID` (Roll No), `EMAIL` (Edu), `PHONE`.
2. **Finance**: `CREDIT_CARD` (PCI-DSS), `IFSC_CODE`, `UPI_ID`, `PAN_CARD`.
3. **Healthcare**: `MEDICAL_MRN` (UHID), `ICD10_CODE`, `INSURANCE_ID`.
4. **Government**: `AADHAAR_UID`, `PASSPORT`, `VOTER_ID`, `DRIVING_LIC`.
5. **Employment**: `EMPLOYEE_ID`, `SALARY` (Currency detection), `OFFICIAL_EMAIL`.
6. **Digital**: `IP_ADDRESS`, `MAC_ADDR`, `API_KEY`, `PASSWORD` (Weak patterns).

---

## 4. Logic & Algorithms

### 4.1 The "Deterministic Regex Builder"

* **Problem:** Small LLMs (like Llama-3B) struggle with character counting (e.g., confusing 10 digits vs 12 digits).
* **Solution:** We implemented a Python-based logic layer (`build_regex_from_structure` in `main.py`).
* **How it works:**
1. Analyzes the input string structure (e.g., "A-1234").
2. Identifies character types: `Letter` -> `Hyphen` -> `Digit`.
3. Mathematically constructs the regex: `\b[A-Z]-\d{4}\b`.
4. **Fail-Safe:** The AI model is used to *orchestrate* this, but the logic is deterministic code.



### 4.2 Fail-Closed Workflow

1. **Config Time:** When an Admin creates a rule, the system attempts to `re.compile(pattern)`. If it fails, the API returns HTTP 500 and prevents the save.
2. **Runtime:** If the detection engine throws an exception during a live request, the global exception handler catches it and returns a generic 500 error, ensuring no raw text leaks to the client.

---

## 5. Deployment Guide

### 5.1 Prerequisites

* **OS:** Windows 10/11 with WSL 2 enabled (Ubuntu 20.04+ recommended).
* **Container Runtime:** Docker Desktop.
* **Hardware:** Minimum 4GB RAM allocated to Docker (for the AI model).

### 5.2 Step-by-Step Installation

1. **Clone & Setup**:
```bash
git clone <repo_url>
cd PII_G

```


2. **Install Model (Manual Step)**:
The AI model is too large for Git. Download it manually into the `models/` folder.
```bash
mkdir -p models
# Download Llama-3.2-3B Quantized (approx 2.4GB)
wget -O models/llama-3.2-3b-instruct.Q4_K_M.gguf https://huggingface.co/hugging-quants/Llama-3.2-3B-Instruct-Q4_K_M-GGUF/resolve/main/llama-3.2-3b-instruct-q4_k_m.gguf?download=true

```


3. **Build & Run**:
```bash
docker-compose up --build

```


4. **Verify**:
* **Frontend**: `http://localhost:8000`
* **Docs**: `http://localhost:8000/docs` (Swagger UI)



### 5.3 Resetting the Database

If you modify `init.sql`, you must wipe the existing volume to re-seed the data:

```bash
docker-compose down
docker volume rm pii_g_postgres_data
docker-compose up --build

```

---

## 6. API Documentation

### 6.1 Core Endpoint: Redact

**`POST /redact`**
Accepts raw text and returns a sanitized version based on the selected domain.

**Request:**

```json
{
  "text": "My USN is 1SK11CS017 and phone is 9876543210",
  "domain": "education"
}

```

**Response:**

```json
{
  "original_text": "My USN is 1SK11CS017 and phone is 9876543210",
  "redacted_text": "My USN is [STUDENT_ID] and phone is XXXXXX3210",
  "pii_detected": [
    {
      "entity_type": "STUDENT_ID",
      "start_index": 10,
      "end_index": 20,
      "text_segment": "1SK11CS017",
      "detection_source": "REGEX: Custom (STUDENT_ID)"
    }
  ],
  "metadata": {
    "processing_time_ms": 15,
    "engine_version": "2.1.0 (AI-Ready)"
  }
}

```

### 6.2 Admin Endpoints

* `POST /admin/domain`: Creates a new policy scope.
* `POST /admin/rule`: Adds a specific redaction rule (supports MASK, HASH, REDACT_TAG).
* `POST /admin/generate-regex`: Internal utility that uses the deterministic builder to create regex from examples.

---

## 7. Frontend Features (v2.1)

The UI (`index.html`) is a Single-Page Application (SPA) built with Bootstrap 5.

* **Workflow Overlay**: Toggle the "Show Workflow Info" switch to see an interactive, annotated guide of the data flow.
* **Live Audit Log**: The black "Audit Box" displays the exact JSON response received from the backend, useful for debugging compliance logs.
* **Latency Metrics**: A badge (e.g., `⚡ 12 ms`) shows real-time processing performance.

---

## 8. Troubleshooting & Common Issues

| Issue | Root Cause | Resolution |
| --- | --- | --- |
| **"Local AI Model not loaded"** | The `.gguf` file is missing in the container. | Ensure `models/` folder is populated and `docker-compose.yml` has the correct volume mapping: `- ./models:/app/models`. |
| **Database rules not updating** | `init.sql` only runs on fresh volume creation. | Run `docker volume rm pii_g_postgres_data` and restart. |
| **500 Internal Server Error** | Fail-Closed mechanism triggered. | Check Docker logs (`docker logs <container_id>`) for the specific regex or logic error. |
| **Slow Redaction (>100ms)** | Spacy model cold start or CPU throttling. | Ensure Docker has at least 2 CPUs allocated. Redaction should stabilize to <20ms after the first few requests. |