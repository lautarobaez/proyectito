import configparser
import os

config = configparser.ConfigParser()

# Detecta automáticamente el config.ini que está en la misma carpeta
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")

config.read(CONFIG_PATH)

def get(section, option, fallback=None):
    """Leer un valor del config.ini"""
    try:
        return config.get(section, option)
    except Exception:
        return fallback

def get_int(section, option, fallback=0):
    """Leer un número desde el config.ini"""
    try:
        return config.getint(section, option)
    except Exception:
        return fallback
