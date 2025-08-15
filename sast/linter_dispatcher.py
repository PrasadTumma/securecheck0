import logging
import sys
import os

# Add path to /sast/wrappers directory (relative to this file)
wrapper_dir = os.path.join(os.path.dirname(__file__), "wrappers")
if wrapper_dir not in sys.path:
    sys.path.insert(0, wrapper_dir)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_linter(language: str, file_path: str):
    """
    Run the appropriate linters based on the programming language.
    For languages supported by both Semgrep and CodeQL, run both.
    """
    try:
        from semgrep_wrapper import run_semgrep

        if language == "python":
            from bandit_wrapper import run_bandit
            logger.info(f"Running Bandit, Semgrep, and CodeQL on {file_path} for Python.")
            return (
                run_bandit(file_path) +
                run_semgrep(file_path, language="python")
            )

        elif language == "java":
            from spotbugs_wrapper import run_spotbugs
            logger.info(f"Running SpotBugs, Semgrep, and CodeQL on {file_path} for Java.")
            return (
                run_spotbugs(file_path) +
                run_semgrep(file_path, language="java")
            )

        elif language == "csharp":
            from devskim_wrapper import run_devskim
            logger.info(f"Running DevSkim, Semgrep, and CodeQL on {file_path} for C#.")
            return (
                run_devskim(file_path) +
                run_semgrep(file_path, language="csharp")
            )

        elif language == "javascript":
            from eslint_wrapper import run_eslint
            logger.info(f"Running ESLint, Semgrep, and CodeQL on {file_path} for JavaScript.")
            return (
                run_eslint(file_path) +
                run_semgrep(file_path, language="javascript")
            )

        else:
            logger.warning(f"Unknown language '{language}'. Attempting Semgrep fallback.")
            try:
                return run_semgrep(file_path, language=language)
            except Exception as e:
                logger.warning(f"Semgrep failed for unknown language: {e}")
                return []

    except ImportError as e:
        logger.error(f"Error importing linter modules: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error during linter execution: {str(e)}")
        return []

# Example usage
if __name__ == "__main__":
    test_language = "python"
    test_file = "example.py"
    results = run_linter(test_language, test_file)
    print(results)
