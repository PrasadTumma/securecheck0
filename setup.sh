#!/bin/bash

# setup.sh - SecureCheck dependency installer with error handling
# Usage: chmod +x setup.sh && ./setup.sh

LOGFILE="setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== SecureCheck Setup Started ====="
date

# Function to run commands safely
run_cmd() {
    local cmd="$1"
    local desc="$2"

    echo "[INFO] Installing: $desc"
    eval "$cmd"
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed: $desc"
        echo "Command: $cmd"
        echo "See $LOGFILE for details."
        exit 1
    else
        echo "[OK] $desc installed successfully."
    fi
}

# Ensure sudo is available
if ! command -v sudo >/dev/null 2>&1; then
    echo "[ERROR] sudo is required to run this script."
    exit 1
fi

# Update system
run_cmd "sudo apt-get update -y" "System package index update"
run_cmd "sudo apt-get upgrade -y" "System upgrade"

# Install Python + pip
run_cmd "sudo apt-get install -y python3 python3-pip python3-venv" "Python & pip"

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    run_cmd "python3 -m venv venv" "Python virtual environment"
else
    echo "[INFO] Virtual environment already exists."
fi

# Activate venv
source venv/bin/activate

# Install Python dependencies
if [ -f "requirements.txt" ]; then
    run_cmd "pip install -r requirements.txt" "Python dependencies from requirements.txt"
else
    echo "[WARN] No requirements.txt found, skipping."
fi

# Install Streamlit
run_cmd "pip install streamlit" "Streamlit"

# Install Bandit
run_cmd "pip install bandit" "Bandit (Python security scanner)"

# Install Semgrep
run_cmd "pip install semgrep" "Semgrep (static analysis tool)"

# Install ESLint
if ! command -v npm >/dev/null 2>&1; then
    run_cmd "sudo apt-get install -y npm nodejs" "Node.js & npm"
fi
run_cmd "sudo npm install -g eslint" "ESLint (JavaScript security scanner)"

# Install SpotBugs
if [ ! -f "spotbugs.tgz" ]; then
    run_cmd "wget -O spotbugs.tgz https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz" "SpotBugs archive"
fi
if [ ! -d "spotbugs" ]; then
    run_cmd "tar -xvzf spotbugs.tgz -C . && mv spotbugs-4.8.3 spotbugs" "Extract SpotBugs"
else
    echo "[INFO] SpotBugs already extracted."
fi

# Install DevSkim
if [ ! -f "devskim.zip" ]; then
    run_cmd "wget -O devskim.zip https://github.com/microsoft/DevSkim/releases/latest/download/devskim_linux.zip" "DevSkim archive"
fi
if [ ! -d "devskim" ]; then
    run_cmd "unzip devskim.zip -d devskim" "Extract DevSkim"
else
    echo "[INFO] DevSkim already extracted."
fi

# Install Syft
if ! command -v syft >/dev/null 2>&1; then
    run_cmd "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh" "Syft (SBOM generator)"
else
    echo "[INFO] Syft already installed."
fi

# Install Grype
if ! command -v grype >/dev/null 2>&1; then
    run_cmd "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh" "Grype (vulnerability scanner)"
else
    echo "[INFO] Grype already installed."
fi

# Install FFUF
if ! command -v ffuf >/dev/null 2>&1; then
    run_cmd "sudo apt-get install -y ffuf" "FFUF (fuzzer)"
else
    echo "[INFO] FFUF already installed."
fi

# Install Nuclei
if ! command -v nuclei >/dev/null 2>&1; then
    run_cmd "sudo apt-get install -y nuclei" "Nuclei (DAST scanner)"
else
    echo "[INFO] Nuclei already installed."
fi

# Install Docker
if ! command -v docker >/dev/null 2>&1; then
    run_cmd "sudo apt-get install -y docker.io" "Docker"
    run_cmd "sudo systemctl enable docker --now" "Enable Docker"
else
    echo "[INFO] Docker already installed."
fi

# Install Dastardly (Docker image)
if ! docker images | grep -q "portswigger/dastardly"; then
    run_cmd "sudo docker pull portswigger/dastardly" "Dastardly (Docker)"
else
    echo "[INFO] Dastardly already installed."
fi

echo "===== SecureCheck Setup Completed Successfully ====="
date
