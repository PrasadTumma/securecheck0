import subprocess
import json
import logging
import asyncio
import shutil
import tempfile
import os 
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_command(command: list) -> str:
    """
    Run a shell command asynchronously and return the output.
    
    :param command: The command to run as a list.
    :return: The output of the command.
    """
    logger.info(f"Running command: {' '.join(command)}")
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.error(f"Command failed with error: {stderr.decode().strip()}")
        raise Exception(f"Command '{' '.join(command)}' failed: {stderr.decode().strip()}")

    return stdout.decode().strip()

def docker_is_available() -> bool:
    return shutil.which("docker") is not None

def build_temp_docker_image(requirements_path: str) -> str:
    temp_dir = tempfile.mkdtemp()
    shutil.copy(requirements_path, os.path.join(temp_dir, "requirements.txt"))

    dockerfile_content = r"""
    FROM python:3.10-slim

    RUN apt-get update && apt-get install -y \
        build-essential \
        gcc \
        g++ \
        make \
        python3-dev \
        libffi-dev \
        libssl-dev \
        python3-distutils && \
        rm -rf /var/lib/apt/lists/*

    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    CMD ["python3"]
    """

    dockerfile_path = os.path.join(temp_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)

    image_tag = f"securecheck-temp-sbom:{os.getpid()}"
    logger.info(f"Building Docker image {image_tag} from requirements.txt")
    subprocess.run(["docker", "build", "--no-cache", "-t", image_tag, temp_dir], check=True)
    return image_tag

def pip_install_to_temp_dir(requirements_path: str) -> str:
    temp_env = tempfile.mkdtemp()
    logger.info("Installing requirements.txt into isolated dir for scanning...")
    subprocess.run(
        ["pip", "install", "-r", requirements_path, "--target", temp_env],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return temp_env

async def generate_sbom(source: str, *, is_requirements: bool = False, use_docker: bool = False) -> dict:
    if shutil.which("syft") is None:
        raise EnvironmentError("Syft is not installed or not in PATH")

    sbom_output = None
    if is_requirements and os.path.isfile(source):
        try:
            if docker_is_available() and use_docker:
                image_tag = build_temp_docker_image(source)
                syft_command = ["syft", image_tag, "-o", "json"]
                sbom_output = await run_command(syft_command)
                logger.info(f"Removing temporary Docker image: {image_tag}")
                subprocess.run(["docker", "rmi", image_tag], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif not use_docker:
                temp_env = pip_install_to_temp_dir(source)
                try:
                    syft_command = ["syft", temp_env, "-o", "json"]
                    sbom_output = await run_command(syft_command)
                finally:
                    logger.info(f"Cleaning up temp folder: {temp_env}")
                    shutil.rmtree(temp_env, ignore_errors=True)
            else:
                raise RuntimeError("Docker is required but not available.")
        except Exception as e:
            logger.error(f"SBOM generation failed: {e}")
            raise
    else:
        syft_command = ["syft", source, "-o", "json"]
        sbom_output = await run_command(syft_command)

    sbom = json.loads(sbom_output)
    logger.info(f"SBOM generated with {len(sbom.get('artifacts', []))} components.")
    return sbom

async def analyze_vulnerabilities(sbom: dict) -> dict:
    if shutil.which("grype") is None:
        raise EnvironmentError("Grype is not installed or not in PATH")

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".json") as f:
        json.dump(sbom, f)
        f.flush()
        grype_command = ["grype", f"sbom:{f.name}", "-o", "json"]

    process = await asyncio.create_subprocess_exec(
        *grype_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.error(f"Grype analysis failed with error: {stderr.decode().strip()}")
        raise Exception(f"Grype analysis failed: {stderr.decode().strip()}")

    grype_output = json.loads(stdout.decode().strip())
    logger.info(f"Grype scan found {len(grype_output.get('matches', []))} vulnerabilities.")
    return grype_output

async def run_sbom_analysis(input_data: str, use_docker: bool = True) -> dict:
    try:
        is_requirements_txt = input_data.strip().endswith(".txt")
        sbom = await generate_sbom(
            input_data,
            is_requirements=is_requirements_txt,
            use_docker=use_docker
        )
        vulnerabilities = await analyze_vulnerabilities(sbom)
        return {
            "sbom": sbom,
            "vulnerabilities": vulnerabilities
        }
    except Exception as e:
        logger.error(f"Error during SBOM analysis: {str(e)}")
        return {
            "error": str(e)
        }

async def main(image_name: str):
    logger.info(f"Starting SBOM analysis for image: {image_name}")
    result = await run_sbom_analysis(image_name)
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    image_name = "your_image_name_here"  # Replace with the actual image name
    asyncio.run(main(image_name))
