"""Configuration module."""

import configparser
import os

config = configparser.ConfigParser()

config.read(os.path.join(os.path.dirname(__file__), 'sten.conf'))

T = '1'
F = '0'

config_default = {
    (section_preferences := 'PREFERENCES'): {
        (option_confirm_exit := 'ConfirmExit'): T,
        (option_mask_key := 'MaskKey'): '*',
        (option_mode_zoomed := 'ModeZoomed'): F,
    },
}

for section, option_default in config_default.items():
    if not config.has_section(section):
        config[section] = option_default
    else:
        for option, default in option_default.items():
            if not config.has_option(section, option):
                config[section][option] = default

CONFIRM_EXIT = config[section_preferences][option_confirm_exit] == T
MASK_KEY = config[section_preferences][option_mask_key]
MODE_ZOOMED = config[section_preferences][option_mode_zoomed] == T
