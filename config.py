"""Configuration module."""

import os
from configparser import ConfigParser

parser = ConfigParser()

parser.read(os.path.join(os.path.dirname(__file__), 'sten.conf'))

config = {
    (section_preferences := 'PREFERENCES'): {
        (option_confirm_exit := 'ConfirmExit'): '1',
        (option_mask_key := 'MaskKey'): '*',
        (option_mode_zoomed := 'ModeZoomed'): '0',
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
MASK_KEY = parser[section_preferences][option_mask_key]
MODE_ZOOMED = parser[section_preferences][option_mode_zoomed] == '1'
