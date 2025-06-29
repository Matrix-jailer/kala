FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Chromium, ChromeDriver, and headless browsing
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    gnupg2 \
    ca-certificates \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libgdk-pixbuf2.0-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxss1 \
    libgbm1 \
    libu2f-udev \
    xdg-utils \
    chromium \
    unzip \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Install Node.js for potential Puppeteer compatibility (optional, kept for flexibility)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs npm

# Install ChromeDriver matching Chromium version
RUN CHROMEDRIVER_VERSION=$(chromium --version | grep -oP '\d+\.\d+\.\d+\.\d+' || echo "126.0.6478.126") && \
    curl -sSL -o /tmp/chromedriver.zip https://storage.googleapis.com/chrome-for-testing-public/${CHROMEDRIVER_VERSION}/linux64/chromedriver-linux64.zip && \
    unzip /tmp/chromedriver.zip -d /usr/local/bin/ && \
    mv /usr/local/bin/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver && \
    chmod +x /usr/local/bin/chromedriver && \
    rm -rf /tmp/chromedriver.zip

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps

# Copy application code
COPY . .

# Expose port for Render
EXPOSE 10000

# Set environment variable for Python
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
