"""Hook modules for sitecustomize injection."""

from malwi_box.hooks.review_hook import BLOCKLIST as REVIEW_BLOCKLIST
from malwi_box.hooks.review_hook import setup_hook as setup_review_hook
from malwi_box.hooks.run_hook import setup_hook as setup_run_hook

__all__ = ["setup_run_hook", "setup_review_hook", "REVIEW_BLOCKLIST"]
