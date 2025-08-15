import json
import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_lessons(filepath: str = "learn/cwe_lessons.json") -> Dict[str, Any]:
    """Load lessons from the specified JSON file."""
    try:
        with open(filepath, 'r') as f:
            lessons = json.load(f)
            logger.info("Lessons loaded successfully from %s.", filepath)
            return lessons
    except FileNotFoundError:
        logger.error("Lessons file not found: %s", filepath)
        return {}
    except json.JSONDecodeError:
        logger.error("Error decoding JSON from the lessons file: %s", filepath)
        return {}
    except Exception as e:
        logger.error("An unexpected error occurred while loading lessons: %s", str(e))
        return {}

def get_lessons_for(cwe_list: List[str], lesson_db: Dict[str, Any]) -> Dict[str, Any]:
    """Get lessons for the specified CWEs from the lesson database."""
    lessons = {}
    for cwe in cwe_list:
        lesson = lesson_db.get(cwe)
        if lesson:
            lessons[cwe] = lesson
            logger.info("Found lesson for CWE ID: %s", cwe)
        else:
            logger.warning("No lesson found for CWE ID: %s", cwe)
    return lessons

# Example usage
if __name__ == "__main__":
    lesson_db = load_lessons()
    cwe_ids = ["CWE-79", "CWE-89", "CWE-22"]  # Example CWE IDs
    lessons = get_lessons_for(cwe_ids, lesson_db)
    print(json.dumps(lessons, indent=4))
