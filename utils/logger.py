import logging
import os
from typing import Optional

_logger: Optional[logging.Logger] = None


def _ensure_configured() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger

    # Ensure logs directory exists at project root
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    log_dir = os.path.join(root, "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "gcrc_execution.log")

    logger = logging.getLogger("gcrc")
    logger.setLevel(logging.DEBUG)

    # Avoid adding multiple handlers on repeated imports
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == os.path.abspath(log_file) for h in logger.handlers):
        fh = logging.FileHandler(log_file)
        fmt = "%(asctime)s | %(levelname)s | %(component)s | %(message)s"
        fh.setFormatter(logging.Formatter(fmt))
        logger.addHandler(fh)
        logger.propagate = False

    _logger = logger
    return _logger


def get_logger(component_name: str) -> logging.Logger:
    """Return a logger adapter that includes a `component` field.

    Usage: logger = get_logger("Layer3-Holliday")
    Then use logger.debug/info/warning/error as normal.
    """

    base = _ensure_configured()
    return logging.LoggerAdapter(base, {"component": component_name}) # type: ignore
