import os
import importlib.resources

VERSION = "0.2.1"

API_BASE_URL = os.getenv(
    "DVARA_API_URL",
    "http://13.61.0.125:8000"
)
DEFAULT_FILTER_PATH = os.getenv(
    "DVARA_FILTER_PATH",
    os.path.join(os.path.expanduser("~"), ".dvara", "filter.bin"),
)

BUNDLED_FILTER_PATH = str(
    importlib.resources.files("dvara").joinpath("data/filter.bin")
)