from importlib.metadata import version

from malwi_box.engine import BoxEngine
from malwi_box.formatting import extract_decision_details, format_event
from malwi_box.hook import (
    install_hook,
    set_event_blocklist,
    uninstall_hook,
)

__all__ = [
    "install_hook",
    "uninstall_hook",
    "set_event_blocklist",
    "BoxEngine",
    "format_event",
    "extract_decision_details",
    "__version__",
]
__version__ = version("malwi-box")
