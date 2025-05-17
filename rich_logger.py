from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install as traceback_install
import logging
import sys

# Install rich traceback globally
traceback_install(show_locals=True, width=120)

class RichLogger:
    _console = Console()
    _initialized = False

    @classmethod
    def setup(cls, level=logging.INFO, log_file=None):
        if cls._initialized:
            return
        handlers = [RichHandler(console=cls._console, show_time=True, show_level=True, show_path=True, markup=True)]
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            handlers.append(file_handler)
        logging.basicConfig(
            level=level,
            format='%(message)s',
            handlers=handlers,
            force=True
        )
        cls._initialized = True

    @classmethod
    def get_logger(cls, name=None):
        cls.setup()
        return logging.getLogger(name)

