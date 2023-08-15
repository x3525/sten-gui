"""This file contains constants."""

##############
# Extensions #
##############
EXTENSIONS_ALL = (
    '*.*',
)
EXTENSIONS_PICTURE = (
    '.bmp',
    '.png',
)
EXTENSIONS_PICTURE_PRETTY = '|'.join(e for e in EXTENSIONS_PICTURE)

#########
# Modes #
#########
MODES_PICTURE = (
    'RGB',
    'RGBA',
)
MODES_PICTURE_PRETTY = '|'.join(m for m in MODES_PICTURE)

###########
# Borders #
###########
B_NONE = 0
B_THIN = 2
B_WIDE = 5

##########
# Colors #
##########
BLACK = '#000000'
BLUE = '#0000FF'
BUTTON = '#F0F0F0'
GREEN = '#00FF00'
RED = '#FF0000'
WHITE = '#FFFFFF'

############
# Paddings #
############
PADX = (5.0, 5.0)
PADY = (5.0, 5.0)

##################
# Virtual Events #
##################
V_EVENT_COPY = '<<Copy>>'
V_EVENT_CUT = '<<Cut>>'
V_EVENT_DECODE = '<<_Decode_>>'
V_EVENT_ENCODE = '<<_Encode_>>'
V_EVENT_OPEN_FILE = '<<_OpenFile_>>'
V_EVENT_OPEN_TEXT = '<<_OpenText_>>'
V_EVENT_PASTE = '<<Paste>>'
V_EVENT_REDO = '<<Redo>>'
V_EVENT_SELECT_ALL = '<<SelectAll>>'
V_EVENT_UNDO = '<<Undo>>'

#############
# Sequences #
#############
SEQUENCE_COPY = ('<Control-Key-c>', '<Control-Lock-Key-C>')
SEQUENCE_CUT = ('<Control-Key-x>', '<Control-Lock-Key-X>')
SEQUENCE_DECODE = ('<Control-Key-d>', '<Control-Lock-Key-D>')
SEQUENCE_ENCODE = ('<Control-Key-e>', '<Control-Lock-Key-E>')
SEQUENCE_OPEN_FILE = ('<Control-Key-n>', '<Control-Lock-Key-N>')
SEQUENCE_PASTE = ('<Control-Key-v>', '<Control-Lock-Key-V>')
SEQUENCE_REDO = ('<Control-Key-y>', '<Control-Lock-Key-Y>')
SEQUENCE_SELECT_ALL = ('<Control-Key-a>', '<Control-Lock-Key-A>')
SEQUENCE_UNDO = ('<Control-Key-z>', '<Control-Lock-Key-Z>')

#############
# Shortcuts #
#############
SHORTCUT_COPY = 'Ctrl+C'
SHORTCUT_CUT = 'Ctrl+X'
SHORTCUT_DECODE = 'Ctrl+D'
SHORTCUT_ENCODE = 'Ctrl+E'
SHORTCUT_OPEN_FILE = 'Ctrl+N'
SHORTCUT_PASTE = 'Ctrl+V'
SHORTCUT_REDO = 'Ctrl+Y'
SHORTCUT_SELECT_ALL = 'Ctrl+A'
SHORTCUT_UNDO = 'Ctrl+Z'

#################
# Miscellaneous #
#################
RGB = 3

B = 8

DELIMITER = '$t3nb7$3rh@tC3l!k'

MIN_PIXEL = B + (B * len(DELIMITER))

ENTRY_SHOW_CHAR = '*'
