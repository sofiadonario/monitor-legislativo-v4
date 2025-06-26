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

# Layer 2: Install asyncpg FIRST before any other dependencies
RUN pip install --no-cache-dir --upgrade "asyncpg==0.29.0"

# Layer 3: Verify asyncpg installation
RUN python -c "import asyncpg; print(f'AsyncPG version installed: {asyncpg.__version__}'); assert asyncpg.__version__ == '0.29.0', f'Wrong version: {asyncpg.__version__}'"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Layer 4: Force reinstall asyncpg after all dependencies (CRITICAL FAILSAFE)
RUN pip install --no-cache-dir --upgrade --force-reinstall "asyncpg==0.29.0"

# Layer 5: Final verification that asyncpg is still correct version
RUN python -c "import asyncpg; print(f'Final AsyncPG version: {asyncpg.__version__}'); assert asyncpg.__version__ == '0.29.0', f'Final verification failed: {asyncpg.__version__}'"

# Stage 2: Create the final production image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy the application code
COPY . .

# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Expose the port the app will run on
EXPOSE 8080

# CRITICAL DEBUGGING: Print runtime environment details before starting the app
# This will help us identify the exact asyncpg version being used at runtime
CMD ["sh", "-c", "echo '=== RAILWAY RUNTIME ENVIRONMENT DEBUG ===' && \
    echo 'Python version:' && python --version && \
    echo 'Pip version:' && pip --version && \
    echo '=== ASYNCPG VERSION CHECK ===' && \
    pip freeze | grep -i asyncpg && \
    echo '=== SQLALCHEMY VERSION CHECK ===' && \
    pip freeze | grep -i sqlalchemy && \
    echo '=== ALL DATABASE-RELATED PACKAGES ===' && \
    pip freeze | grep -iE '(asyncpg|sqlalchemy|psycopg|postgres)' && \
    echo '=== TESTING ASYNCPG IMPORT ===' && \
    python -c 'import asyncpg; print(f\"asyncpg version: {asyncpg.__version__}\")' && \
    echo '=== FULL DEPENDENCY TREE FOR ASYNCPG ===' && \
    pip show asyncpg && \
    echo '=== ENVIRONMENT VARIABLES ===' && \
    env | grep -iE '(database|railway|supabase)' && \
    echo '=== FINAL ASYNCPG VERSION VERIFICATION ===' && \
    python -c 'import asyncpg; v=asyncpg.__version__; print(f\"Runtime AsyncPG: {v}\"); parts=v.split(\".\"); major,minor=int(parts[0]),int(parts[1]); compatible=major>0 or (major==0 and minor>=26); print(f\"Supabase compatible: {compatible}\"); exit(0 if compatible else 1)' && \
    echo '=== STARTING APPLICATION ===' && \
    uvicorn main_app.main:app --host 0.0.0.0 --port 8080"] 