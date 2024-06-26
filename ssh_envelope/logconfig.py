import logging

def setup_logging():
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

setup_logging()
