# -----------------------------
# Base image
# -----------------------------
FROM ubuntu:24.04

# -----------------------------
# Install system dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    python3.11 python3.11-venv python3-pip \
    openjdk-20-jdk \
    nodejs npm \
    git wget curl unzip \
    build-essential \
    software-properties-common \
    && apt-get clean

# -----------------------------
# Install SpotBugs
# -----------------------------
RUN wget https://github.com/spotbugs/spotbugs/releases/download/4.8.2/spotbugs-4.8.2.tgz \
    && tar -xzf spotbugs-4.8.2.tgz -C /opt/ \
    && rm spotbugs-4.8.2.tgz
ENV SPOTBUGS_HOME=/opt/spotbugs-4.8.2
ENV PATH=$SPOTBUGS_HOME/bin:$PATH

# -----------------------------
# Install Node.js tools (ESLint)
# -----------------------------
RUN npm install -g eslint

# -----------------------------
# Install Python dependencies
# -----------------------------
# Copy requirements first for caching
COPY requirements.txt /app/requirements.txt

# Create Python virtual environment
RUN python3.11 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r /app/requirements.txt

# -----------------------------
# Install Nuclei (DAST scanner)
# -----------------------------
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei-linux-amd64.tar.gz \
    | tar -xz -C /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei

# -----------------------------
# Install Dastardly (if needed, example)
# -----------------------------
RUN git clone https://github.com/your-org/dastardly.git /opt/dastardly \
    && cd /opt/dastardly \
    && npm install -g

# -----------------------------
# Set working directory
# -----------------------------
WORKDIR /app
COPY . /app

# -----------------------------
# Expose Streamlit port
# -----------------------------
EXPOSE 8501

# -----------------------------
# Run the app
# -----------------------------
CMD ["streamlit", "run", "ui.py", "--server.port=8501", "--server.address=0.0.0.0"]
