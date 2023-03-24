"""Configuration module."""

import os
from configparser import ConfigParser

parser = ConfigParser()

parser.read(os.path.join(os.path.dirname(__file__), 'sten.conf'))

config = {
    (section_preferences := 'PREFERENCES'): {
        (option_confirm_exit := 'ConfirmExit'): '1',
        (option_key_mask := 'KeyMask'): '*',
        (option_zoomed_mode := 'ZoomedMode'): '0',
    },
}

for section, option_default in config.items():
    if not parser.has_section(section):
        parser[section] = option_default
    else:
        for option, default in option_default.items():
            if not parser.has_option(section, option):
                parser[section][option] = default

CONFIRM_EXIT = parser[section_preferences][option_confirm_exit] == '1'
KEY_MASK = parser[section_preferences][option_key_mask]
ZOOMED_MODE = parser[section_preferences][option_zoomed_mode] == '1'
