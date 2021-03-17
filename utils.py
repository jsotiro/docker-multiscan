import logging

log_format = '%(asctime)s.%(msecs)03d %(levelname)s] %(message)s'
logging.basicConfig(format=log_format, datefmt='%Y-%m-%d,%H:%M:%S', level=logging.DEBUG)
