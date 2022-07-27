import logging

from logging import FileHandler
from logging import Formatter

LOG_FORMAT = ("%(asctime)s [%(levelname)s]: %(message)s in %(pathname)s:%(lineno)d")
LOG_LEVEL = logging.WARN
ALARMAS_LOG_FILE = "/var/log/hips/alarmas.log"
alarmas_logger = logging.getLogger("var.log.hips.alarmas")
alarmas_logger.setLevel(LOG_LEVEL)
alarmas_logger_file_handler = FileHandler(ALARMAS_LOG_FILE)
alarmas_logger_file_handler.setFormatter(Formatter(LOG_FORMAT))
alarmas_logger.addHandler(alarmas_logger_file_handler)

