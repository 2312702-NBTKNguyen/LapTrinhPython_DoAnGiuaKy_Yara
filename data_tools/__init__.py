from collections.abc import Callable


def _log(log_callback: Callable[[str], None] | None, message: str) -> None:
    if log_callback:
        log_callback(message)
