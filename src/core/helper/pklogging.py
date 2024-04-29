import logging

# TODO: use `logging` library for colored outputs
# logging.basicConfig(format='\033[30;47m[%(levelname)s | %(asctime)s] - %(message)s\033[0m', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
# logging.basicConfig(format='\033[36;40m[%(levelname)s | %(asctime)s] - %(message)s\033[0m', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
# logging.basicConfig(format='\033[33;40m[%(levelname)s | %(asctime)s] - %(message)s\033[0m', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.WARNING)
# logging.basicConfig(format='\033[31;40m[%(levelname)s | %(asctime)s] - %(message)s\033[0m', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.ERROR)
# logging.basicConfig(format='\033[30;41m[%(levelname)s | %(asctime)s] - %(message)s\033[0m', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.CRITICAL)

def debug(message):
    logging.debug(message)

def info(message):
    logging.info(message)

def warning(message):
    logging.warning(message)

def error(message):
    logging.error(message)

def critical(message):
    logging.critical(message)