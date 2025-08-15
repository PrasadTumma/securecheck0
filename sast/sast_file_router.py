import os
import importlib.util
import logging
from typing import Optional, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FileRouter:
    def __init__(self):
        # Mapping of file extensions to their handler modules
        self.handler_map = {
            '.py': 'python_handler',
            '.java': 'java_handler',
            '.cs': 'csharp_handler',
            '.js': 'javascript_handler',
        }
        
        # Extensions supported by Semgrep fallback
        self.semgrep_extensions = {
            '.ts', '.kt', '.go', '.php', '.rb', '.cpp', '.c', '.swift'
        }

    def get_file_extension(self, file_path: str) -> Optional[str]:
        try:
            _, ext = os.path.splitext(file_path)
            return ext.lower() if ext else None
        except Exception as e:
            logger.error(f"Error extracting file extension: {str(e)}")
            return None

    def get_handler_module(self, file_path: str) -> str:
        ext = self.get_file_extension(file_path)
        if not ext:
            return "fallback"
        return self.handler_map.get(ext, "fallback")

    def route_file(self, file_path: str, ai_enabled: bool = True) -> Dict:
        try:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            handler_module = self.get_handler_module(file_path)

            if handler_module != "fallback":
                module_path = os.path.join(os.path.dirname(__file__), "handlers", f"{handler_module}.py")
                spec = importlib.util.spec_from_file_location(handler_module, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                handler = getattr(module, f"handle_{handler_module.replace('_handler', '')}")

                language = handler_module.replace('_handler', '')
                logger.info(f"Using dedicated handler for: {language}")

                return {
                    "status": "success",
                    "handler": handler_module,
                    "language": language,
                    "results": handler(file_path, ai_enabled=ai_enabled)
                }
            else:
                return self.fallback_handler(file_path, ai_enabled=ai_enabled)

        except FileNotFoundError:
            return self.handle_error(file_path, "File not found.")

        except Exception as e:
            return self.handle_error(file_path, str(e))

    def fallback_handler(self, file_path: str, ai_enabled: bool = True) -> Dict:
        try:
            ext = self.get_file_extension(file_path)
            language = ext.lstrip('.') if ext else "unknown"
            results = []

            from sast.wrappers.semgrep_wrapper import run_semgrep
            results.extend(run_semgrep(file_path, language))

            return {
                "status": "fallback",
                "handler": "semgrep",
                "language": language,
                "results": results
            }

        except Exception as e:
            return self.handle_error(file_path, f"Fallback failed: {str(e)}")

    def handle_error(self, file_path: str, error_msg: str) -> Dict:
        logger.error(f"Failed to process {file_path}: {error_msg}")
        return {
            "status": "error",
            "file": file_path,
            "error": error_msg
        }

if __name__ == "__main__":
    import json
    router = FileRouter()
    test_files = [
        "example.py", "Example.java", "test.cs", "app.js",
        "main.ts", "program.go", "random.php", "noext", "unknown.xyz"
    ]
    for file in test_files:
        print(f"\nProcessing {file}:")
        result = router.route_file(file, ai_enabled=True)
        print(json.dumps(result, indent=2))