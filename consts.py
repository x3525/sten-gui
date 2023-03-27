"""This file contains constants."""

# no imports

# = URLs =
URL = 'https://github.com/serhatcelik/sten'  # No trailing slash!
URL_ARCHIVE = f'{URL}/archive/refs/tags/'  # Do not remove the trailing slash!
URL_LATEST_VERSION = f'{URL}/releases/latest'

# = Extensions =
EXTENSIONS_ALL = ['*.*']
EXTENSIONS_PICTURE = [
    '.bmp',
    '.png',
]
EXTENSIONS_PICTURE_PRETTY = '|'.join(_ for _ in EXTENSIONS_PICTURE)

# = Modes =
MODES_PICTURE = [
    'RGB',
    'RGBA',
]
MODES_PICTURE_PRETTY = '|'.join(_ for _ in MODES_PICTURE)

# = Colors =
BLACK = '#000000'
BLUE = '#0000FF'
BUTTON = '#F0F0F0'
CYAN = '#00FFFF'
GREEN = '#00FF00'
HIGHLIGHT = '#0078D7'
RED = '#FF0000'
WHITE = '#FFFFFF'

# = V Events =
# == Custom V Events ==
VIRTUAL_EVENT_DECODE = '<<v_event_Decode>>'
VIRTUAL_EVENT_ENCODE = '<<v_event_Encode>>'
VIRTUAL_EVENT_OPEN_FILE = '<<v_event_OpenFile>>'
VIRTUAL_EVENT_OPEN_TEXT = '<<v_event_OpenText>>'

# == Predefined V Events ==
VIRTUAL_EVENT_COPY = '<<Copy>>'
VIRTUAL_EVENT_CUT = '<<Cut>>'
VIRTUAL_EVENT_PASTE = '<<Paste>>'
VIRTUAL_EVENT_REDO = '<<Redo>>'
VIRTUAL_EVENT_SELECT_ALL = '<<SelectAll>>'
VIRTUAL_EVENT_UNDO = '<<Undo>>'

# = Sequences =
SEQUENCE_COPY = ['<Control-Key-c>', '<Control-Lock-Key-C>']
SEQUENCE_CUT = ['<Control-Key-x>', '<Control-Lock-Key-X>']
SEQUENCE_DECODE = ['<Control-Key-d>', '<Control-Lock-Key-D>']
SEQUENCE_ENCODE = ['<Control-Key-e>', '<Control-Lock-Key-E>']
SEQUENCE_OPEN_FILE = ['<Control-Key-n>', '<Control-Lock-Key-N>']
SEQUENCE_PASTE = ['<Control-Key-v>', '<Control-Lock-Key-V>']
SEQUENCE_REDO = ['<Control-Key-y>', '<Control-Lock-Key-Y>']
SEQUENCE_SELECT_ALL = ['<Control-Key-a>', '<Control-Lock-Key-A>']
SEQUENCE_UNDO = ['<Control-Key-z>', '<Control-Lock-Key-Z>']

# = Shortcuts =
SHORTCUT_COPY = 'Ctrl+C'
SHORTCUT_CUT = 'Ctrl+X'
SHORTCUT_DECODE = 'Ctrl+D'
SHORTCUT_ENCODE = 'Ctrl+E'
SHORTCUT_OPEN_FILE = 'Ctrl+N'
SHORTCUT_PASTE = 'Ctrl+V'
SHORTCUT_REDO = 'Ctrl+Y'
SHORTCUT_SELECT_ALL = 'Ctrl+A'
SHORTCUT_UNDO = 'Ctrl+Z'

# = Miscellaneous =
IPADY = 10.0

PADX = (5.0, 5.0)
PADY = (5.0, 5.0)

B = 8  # 8-bits = 1-Byte

DELIMITER = '$t3nb7$3rh@tC3l!k'
