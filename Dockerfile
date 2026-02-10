# [File: Dockerfile]
FROM python:3.9

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- BRAIN TRANSPLANT: Install English (Large) & Multi-lang (Small) ---
# 'en_core_web_lg' gives best accuracy for English
# 'xx_ent_wiki_sm' is the standard for Hindi/Multi-lang NER
RUN python -m spacy download en_core_web_lg
RUN python -m spacy download xx_ent_wiki_sm

COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]