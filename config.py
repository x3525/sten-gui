"""Configuration module."""

import configparser
import os

_CONFIG = configparser.ConfigParser()

_CONFIG.read(os.path.join(os.path.dirname(__file__), 'sten.conf'))

_DEFAULT_CONFIG = {
    (_SECTION_PREFERENCES := 'PREFERENCES'): {
        (_OPTION_CIPHER_KEY_MASK := 'CipherKeyMask'): '*',
        (_OPTION_CONFIRM_EXIT := 'ConfirmExit'): '1',
        (_OPTION_PRNG_SEED_MASK := 'PRNGSeedMask'): '*',
    },
}

for section, option_default in _DEFAULT_CONFIG.items():
    if not _CONFIG.has_section(section):
        _CONFIG[section] = option_default
    else:
        for option, default in option_default.items():
            if not _CONFIG.has_option(section, option):
                _CONFIG[section][option] = default

CIPHER_KEY_MASK = _CONFIG[_SECTION_PREFERENCES][_OPTION_CIPHER_KEY_MASK]
CONFIRM_EXIT = _CONFIG[_SECTION_PREFERENCES][_OPTION_CONFIRM_EXIT]
PRNG_SEED_MASK = _CONFIG[_SECTION_PREFERENCES][_OPTION_PRNG_SEED_MASK]
