"""Configuration module."""

import configparser
import os
from contextlib import suppress

parser = configparser.ConfigParser()

with suppress(configparser.Error):
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
    else:
        for option, default in option_default.items():
            if parser.has_option(section, option):
                if parser[section][option] in parser.BOOLEAN_STATES:
                    continue
            parser[section][option] = default

CONFIRM_EXIT = parser.getboolean(section_preferences, option_confirm_exit)
KEY_MASK = parser[section_preferences][option_key_mask]
ZOOMED_MODE = parser.getboolean(section_preferences, option_zoomed_mode)
