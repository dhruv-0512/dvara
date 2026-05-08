import os
import importlib.resources

VERSION = "0.1.1"

API_BASE_URL = os.getenv(
    "DVARA_API_URL",
    "https://dvara-t19n.onrender.com"
)
DEFAULT_FILTER_PATH = os.getenv(
    "DVARA_FILTER_PATH",
    os.path.join(os.path.expanduser("~"), ".dvara", "filter.bin"),
)

BUNDLED_FILTER_PATH = str(
    importlib.resources.files("dvara").joinpath("data/filter.bin")
)