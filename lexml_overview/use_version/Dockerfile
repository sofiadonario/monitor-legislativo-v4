FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install spaCy model
RUN python -m spacy download pt_core_news_sm

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/{raw,processed,external,models,reports} logs exports

# Expose ports
EXPOSE 8501 8000

# Default command
CMD ["streamlit", "run", "interactive_dashboard.py", "--server.address", "0.0.0.0"]
