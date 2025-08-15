import subprocess
import json
import logging
import shutil
import re
import os
import tempfile
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_java_lib_path() -> str:
    javac_path = shutil.which("javac")
    if not javac_path:
        return ""
    jdk_root = os.path.dirname(os.path.dirname(javac_path))  # /usr/lib/jvm/java-21-openjdk-amd64
    lib_path = os.path.join(jdk_root, "lib", "*")
    return lib_path

def run_spotbugs(file_path: str, classpath: Optional[str] = None) -> List[Dict]:
    try:
        if shutil.which("spotbugs") is None:
            logger.error("SpotBugs is not installed.")
            return []
        if shutil.which("javac") is None:
            logger.error("javac (Java compiler) is not installed.")
            return []

        java_lib_path = get_java_lib_path()

        with tempfile.TemporaryDirectory() as tempdir:
            logger.info(f"Compiling Java file {file_path} to {tempdir}")

            # Build full classpath
            combined_classpath = ""
            if classpath and java_lib_path:
                combined_classpath = f"{classpath}:{java_lib_path}"
            elif classpath:
                combined_classpath = classpath
            elif java_lib_path:
                combined_classpath = java_lib_path

            compile_cmd = [
                "javac",
                "-d", tempdir
            ]

            if combined_classpath:
                compile_cmd += ["-classpath", combined_classpath]

            compile_cmd.append(file_path)

            compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)
            if compile_proc.returncode != 0:
                logger.error(f"javac failed:\n{compile_proc.stderr}")
                return []

            # Run SpotBugs
            spotbugs_cmd = [
                "spotbugs",
                "-textui",
                "-low",
                "-effort:max",
                tempdir
            ]

            logger.info(f"Running SpotBugs: {' '.join(spotbugs_cmd)}")
            result = subprocess.run(spotbugs_cmd, capture_output=True, text=True)

            if result.returncode not in (0, 1):  # 1 = bugs found, 0 = clean
                logger.error(f"SpotBugs failed:\n{result.stderr}")
                return []

            return parse_spotbugs_output(result.stdout)

    except Exception as e:
        logger.exception("Exception while running SpotBugs")
        return []

def parse_spotbugs_output(output: str) -> List[Dict]:
    findings = []
    try:
        pattern = re.compile(r'^(.*\.java):(\d+):\s+\[(.*?)\]\s+(.*?)(?:\s+\(CWE-(\d+)\))?$')
        for line in output.splitlines():
            match = pattern.match(line.strip())
            if match:
                file_name, line_no, severity_text, message, cwe = match.groups()
                findings.append({
                    "file": file_name,
                    "line": int(line_no),
                    "message": message.strip(),
                    "cwe_id": f"CWE-{cwe}" if cwe else None,
                    "tool": "SpotBugs",
                    "severity": severity_text.upper()
                })
    except Exception as e:
        logger.error(f"Error parsing SpotBugs output: {str(e)}")

    return findings


# Example test run
if __name__ == "__main__":
    test_file = "Example.java"  # Replace with actual file
    results = run_spotbugs(test_file, classpath="./libs/servlet-api-2.5.jar")
    print(json.dumps(results, indent=2))
