"""Configuration module."""

import os
from configparser import ConfigParser

parser = ConfigParser(allow_no_value=True, strict=False, interpolation=None)

parser.read(os.path.join(os.path.dirname(__file__), 'sten.conf'))

config = {
    (section_preferences := 'PREFERENCES'): {
        (option_confirm_exit := 'ConfirmExit'): 'yes',
        (option_key_mask := 'KeyMask'): '*',
        (option_zoomed_mode := 'ZoomedMode'): 'no',
    },
}

for section, option_default in config.items():
    if not parser.has_section(section):
        parser[section] = option_default
        continue
    for option, default in option_default.items():
        if parser.has_option(section, option):
            if default not in parser.BOOLEAN_STATES:
                continue
            if parser[section][option].lower() in parser.BOOLEAN_STATES:
                continue
        parser[section][option] = default

CONFIRM_EXIT = parser.getboolean(section_preferences, option_confirm_exit)
KEY_MASK = parser[section_preferences][option_key_mask]
ZOOMED_MODE = parser.getboolean(section_preferences, option_zoomed_mode)
