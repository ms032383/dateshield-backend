# Step 1: Python ka lightweight version use kar rahe hain
FROM python:3.11-slim

# Step 2: System-level software (Tesseract) install karna
# Ye wahi command hai jo Render ke normal environment mein fail ho rahi thi
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Step 3: Working directory set karna
WORKDIR /app

# Step 4: Python libraries install karna
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Pura code copy karna
COPY . .

# Step 6: Server start karna (Port 10000 Render ka default hai)
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]