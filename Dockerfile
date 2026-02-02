# Switching to the full image to speed up AI library installation
FROM python:3.9

# Set working directory
WORKDIR /app

# Install system dependencies (Full image already has gcc/g++)
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the AI Model
RUN python -m spacy download en_core_web_lg

# Copy application code
COPY . .

# Command to run the app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]