import logging
import sys

class Logger:
    """
    A placeholder for a custom Logger class.
    This provides a basic logging setup to allow the application to start.
    """
    _logger = None

    @classmethod
    def get_logger(cls):
        if cls._logger is None:
            logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            cls._logger = logging.getLogger("MonitorLegislativo")
        return cls._logger

# To be compatible with `logger = Logger()`
def __call__(self, *args, **kwargs):
    return self.get_logger() 