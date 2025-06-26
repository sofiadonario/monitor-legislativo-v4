# Stage 1: Build the virtual environment
FROM python:3.11-slim as builder

# Set the working directory
WORKDIR /app

# Create a virtual environment
RUN python -m venv /opt/venv

# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir --upgrade "asyncpg==0.29.0"

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

# Command to run the application
CMD ["uvicorn", "main_app.main:app", "--host", "0.0.0.0", "--port", "8080"] 