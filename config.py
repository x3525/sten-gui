"""Configuration module."""

import configparser
import os

config = configparser.ConfigParser()

config.read(os.path.join(os.path.dirname(__file__), 'sten.conf'))

config_default = {
    (section_preferences := 'PREFERENCES'): {
        (option_confirm_exit := 'ConfirmExit'): '1',
        (option_key_mask := 'KeyMask'): '*',
        (option_zoomed_mode := 'ZoomedMode'): '0',
    },
}

for section, option_default in config_default.items():
    if not config.has_section(section):
        config[section] = option_default
    else:
        for option, default in option_default.items():
            if not config.has_option(section, option):
                config[section][option] = default

CONFIRM_EXIT = config[section_preferences][option_confirm_exit]
KEY_MASK = config[section_preferences][option_key_mask]
ZOOMED_MODE = config[section_preferences][option_zoomed_mode]
