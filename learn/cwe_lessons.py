import json
import logging
import requests
import os
import xml.etree.ElementTree as ET
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CWELessons:
    def __init__(self, static_lessons_path="learn/cwe_lessons.json", cache_path="learn/cwe_cache.json"):
        self.static_lessons_path = static_lessons_path
        self.cache_path = cache_path
        self.lessons = self.load_static_lessons()
        self.cache = self.load_cache()

    def load_static_lessons(self) -> dict:
        """Load static lessons from the specified JSON file."""
        try:
            with open(self.static_lessons_path, 'r') as f:
                lessons = json.load(f)
                logger.info("Static lessons loaded successfully.")
                return lessons
        except FileNotFoundError:
            logger.error(f"Static lessons file not found: {self.static_lessons_path}")
            return {}
        except json.JSONDecodeError:
            logger.error("Error decoding JSON from the static lessons file.")
            return {}
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading static lessons: {str(e)}")
            return {}

    def load_cache(self) -> dict:
        """Load cached CWE descriptions from a JSON file."""
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, 'r') as f:
                    cache = json.load(f)
                    logger.info("Cache loaded successfully.")
                    return cache
            except FileNotFoundError:
                logger.warning(f"Cache file not found: {self.cache_path}. Starting with an empty cache.")
                return {}
            except json.JSONDecodeError:
                logger.error("Error decoding JSON from the cache file.")
                return {}
            except Exception as e:
                logger.error(f"An unexpected error occurred while loading cache: {str(e)}")
                return {}
        return {}

    def fetch_from_cache(self, cwe_id: str) -> dict:
        """Try to retrieve a cached fallback for the given CWE ID."""
        lesson = self.cache.get(cwe_id)
        if lesson:
            logger.info(f"Fetched {cwe_id} from cache.")
        else:
            logger.info(f"{cwe_id} not found in cache.")
        return lesson

    def is_valid_cwe_format(self, cwe_id: str) -> bool:
        """Check if the CWE ID matches the expected format."""
        return bool(re.match(r"^CWE-\d+$", cwe_id))

    def fetch_from_xml(self, cwe_id: str) -> dict:
        """Fetch CWE details from MITRE and parse the XML data."""
        if not self.is_valid_cwe_format(cwe_id):
            logger.warning(f"Invalid CWE ID format: {cwe_id}")
            self.cache[cwe_id] = None
            self.save_cache()
            return None
        try:
            cwe_number = cwe_id.split('-')[1]
            response = requests.get(f"https://cwe.mitre.org/data/definitions/{cwe_number}.xml", timeout=5)
            response.raise_for_status()

            # Parse the XML response
            root = ET.fromstring(response.content)
            title = root.find('.//Title').text or "No title available"
            description = root.find('.//Description').text or "No description available"

            # Create a lesson structure
            lesson = {
                "title": title,
                "summary": description,
                "impact": "Dynamic impact from MITRE.",
                "mitigation": "Dynamic mitigation from MITRE.",
                "examples": {
                    "bad": "Dynamic bad code example.",
                    "good": "Dynamic good code example."
                },
                "source": "mitre"
            }

            # Update cache with the new lesson
            self.cache[cwe_id] = lesson
            self.save_cache()
            logger.info(f"Fetched {cwe_id} from MITRE and updated cache.")
            return lesson
        except requests.RequestException as e:
            logger.error(f"Failed to fetch data from MITRE for {cwe_id}: {str(e)}")
            return None
        except ET.ParseError:
            logger.error(f"Failed to parse XML response for {cwe_id}.")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred while fetching from XML: {str(e)}")
            return None
        
        self.cache[cwe_id] = None
        self.save_cache()
        return None
        
    def save_cache(self) -> None:
        """Save the current cache to a JSON file."""
        try:
            with open(self.cache_path, 'w') as f:
                json.dump(self.cache, f, indent=4)
            logger.info("Cache saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save cache: {str(e)}")

    def get_lesson(self, cwe_id: str) -> dict:
        """Return the full lesson from static, cache, or dynamic fallback."""
        # Check static lessons first
        lesson = self.lessons.get(cwe_id)
        if lesson:
            logger.info(f"Found {cwe_id} in static lessons.")
            return lesson
        
        # Try to fetch from cache
        lesson = self.fetch_from_cache(cwe_id)
        if lesson:
            return lesson
        
        # Fetch from MITRE if not found in static or cache
        lesson = self.fetch_from_xml(cwe_id)
        return lesson

# Example usage
if __name__ == "__main__":
    cwe_lessons = CWELessons()
    cwe_id = "CWE-79"  # Example CWE ID
    lesson = cwe_lessons.get_lesson(cwe_id)
    if lesson:
        print(json.dumps(lesson, indent=4))
    else:
        logger.warning(f"No lesson found for {cwe_id}.")
