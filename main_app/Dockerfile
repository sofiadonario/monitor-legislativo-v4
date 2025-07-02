# Stage 1: Build the virtual environment
FROM python:3.11-slim as builder

# Set the working directory
WORKDIR /app

# Create a virtual environment
RUN python -m venv /opt/venv

# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# CRITICAL: Multiple layers of asyncpg protection
# Layer 1: Update pip to latest version first
RUN pip install --no-cache-dir --upgrade pip

# Layer 2: Install asyncpg FIRST before any other dependencies (0.28.0 for Supabase compatibility)
RUN pip install --no-cache-dir --upgrade "asyncpg==0.28.0"

# Layer 3: Verify asyncpg installation
RUN python -c "import asyncpg; print(f'AsyncPG version installed: {asyncpg.__version__}'); assert asyncpg.__version__ == '0.28.0', f'Wrong version: {asyncpg.__version__}'"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Layer 4: Force reinstall asyncpg after all dependencies (CRITICAL FAILSAFE)
RUN pip install --no-cache-dir --upgrade --force-reinstall "asyncpg==0.28.0"

# Layer 5: Install fallback driver (psycopg) for compatibility
RUN pip install --no-cache-dir --upgrade "psycopg[binary]==3.1.12"

# Layer 6: Final verification that both drivers are installed
RUN python -c "import asyncpg; print(f'Final AsyncPG version: {asyncpg.__version__}'); assert asyncpg.__version__ == '0.28.0', f'Final verification failed: {asyncpg.__version__}'"
RUN python -c "import psycopg; print(f'Psycopg fallback driver: {psycopg.__version__}')"

# Stage 2: Create the final production image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy the application source from the main_app directory into /app
COPY . /app/

# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Expose the port the app will run on
EXPOSE 8080

# Start the application using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]