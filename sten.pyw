# pylint: disable=wrong-import-order

"""Sten — LSB-based image steganography tool.

Copyright (C) 2023  Serhat Çelik

Sten is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Sten is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Sten.  If not, see <https://www.gnu.org/licenses/>.
"""

import itertools
import logging
import math
import os
import random
import string
import sys
import tkinter as tk
import warnings
import webbrowser
from ctypes import windll
from dataclasses import dataclass
from idlelib.tooltip import Hovertip  # type: ignore
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.font import Font
from tkinter.messagebox import (
    askokcancel,
    askretrycancel,
    showerror,
    showinfo,
    showwarning,
)
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Combobox
from typing import List, Optional, Tuple
from urllib.error import URLError
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

import numpy as np
from PIL import Image, UnidentifiedImageError
from numpy.typing import NDArray

import crypto
import data64
from config import (
    CIPHER_KEY_MASK,
    CONFIRM_EXIT,
    PRNG_SEED_MASK,
)
from consts import *
from version import __version__

# Turn matching warnings into exceptions
warnings.simplefilter('error', Image.DecompressionBombWarning)


@dataclass
class Globals:
    """Global 'over control' variables."""

    band_lsb: Tuple[Tuple[int, int], ...]

    ch_limit: int

    is_bound: bool = False


@dataclass
class Picture:
    """Image properties of a previously opened picture file."""

    pixel: int
    imagedata: NDArray
    dimensions: Tuple[int, int]
    mode: str

    filename: str
    extension: str

    properties: List[str]


def t_open_() -> None:
    """Trigger 'VIRTUAL_EVENT_OPEN'."""
    root.event_generate(VIRTUAL_EVENT_OPEN)


def open_(event: tk.Event) -> Optional[str]:
    """Open a picture file."""
    bg_old = btn_open['bg']  # Backup
    btn_open['bg'] = WHITE

    retry = True
    while retry:
        file = askopenfilename(
            filetypes=[('Picture Files', EXTENSIONS_PICTURE)],
            initialdir='~',
            title='Open',
        )
        if not file:
            break

        filename, extension = os.path.splitext(file)

        if extension.casefold() not in EXTENSIONS_PICTURE:
            retry = askretrycancel(
                title='Open',
                message=f'Not a valid extension: {extension}',
                detail=f'Valid extensions: {EXTENSIONS_PICTURE_PRETTY}',
            )
            continue

        try:
            with Image.open(file) as pic:
                pixel = math.prod(pic.size)
                imagedata = list(pic.getdata())
                dimensions = pic.size
                mode = pic.mode
        except (
                FileNotFoundError, PermissionError,
                UnidentifiedImageError, Image.DecompressionBombWarning,
        ) as err:
            retry = askretrycancel(title='Open', message=str(err))
            continue

        if mode not in MODES_PICTURE:
            retry = askretrycancel(
                title='Open',
                message=f'Mode not supported: {mode}',
                detail=f'Supported modes: {MODES_PICTURE_PRETTY}',
            )
            continue

        min_pix = B + (B * len(DELIMITER))

        if pixel < min_pix:
            retry = askretrycancel(
                title='Open',
                message=f'Need minimum {min_pix} pixels.',
                detail=f'Provided: {pixel} pixels',
            )
            continue

        # Important! After all error checks are passed, set attributes here!
        Picture.pixel = pixel
        Picture.imagedata = np.array(imagedata)
        Picture.dimensions = (width, height) = dimensions
        Picture.mode = mode

        Picture.filename = os.path.basename(filename)
        Picture.extension = extension

        ch_capacity = (Picture.pixel * len(band_scl)) - len(DELIMITER)

        Picture.properties = [
            f'Capacity: {ch_capacity} characters',
            f'Width: {width} pixels',
            f'Height: {height} pixels',
            f'Bit depth: {B * len(Picture.mode)} ({Picture.mode})',
            f'Size: {os.stat(file).st_size} bytes',
        ]

        VARIABLE_OPENED.set(f'"{file}"')
        VARIABLE_OUTPUT.set('')

        root.wm_title(root.wm_title().rstrip('*') + '*')

        btn_show['state'] = tk.DISABLED

        btn_open['bg'] = CYAN
        return None

    btn_open['bg'] = bg_old  # Restore
    return 'break'  # No more event processing for 'VIRTUAL_EVENT_OPEN'


def t_open_text() -> None:
    """Trigger 'VIRTUAL_EVENT_OPEN_TEXT'."""
    root.event_generate(VIRTUAL_EVENT_OPEN_TEXT)


def open_text(event: tk.Event) -> Optional[str]:
    """Read the contents of a file as text."""
    file = askopenfilename(
        filetypes=[('All Files', EXTENSIONS_ALL)],
        initialdir='~',
        title='Open Text',
    )
    if not file:
        return 'break'

    try:
        with open(file, 'r', encoding='utf-8', errors='ignore') as out:
            stx_message.delete('1.0', tk.END)
            stx_message.insert('1.0', out.read())
    except (FileNotFoundError, PermissionError) as err:
        showerror(title='Open Text', message=str(err))
        return 'break'
    else:
        return None


def t_encode() -> None:
    """Trigger 'VIRTUAL_EVENT_ENCODE'."""
    root.event_generate(VIRTUAL_EVENT_ENCODE)


def encode(event: tk.Event) -> None:
    """Create a stego-object."""
    message = stx_message.get('1.0', tk.END)[:-1]

    for char in message:
        if char in string.printable:
            continue
        showerror(
            title='Encode',
            message='Message contains a non-ASCII character.',
            detail=f'Character: {char}',
        )
        return

    if DELIMITER in message:
        showwarning(
            title='Encode',
            message='Message contains the delimiter. Some data will be lost.',
            detail=f'Delimiter: {DELIMITER}',
        )

    try:
        cipher = crypto.ciphers[box_ciphers.get()](ent_key.get())
    except ValueError as err:
        showerror(title='Encode', message=str(err))
        return

    output = asksaveasfilename(
        confirmoverwrite=True,
        defaultextension=Picture.extension,
        filetypes=[('Picture Files', EXTENSIONS_PICTURE)],
        initialfile=f'{Picture.filename}-encoded',
        title='Save As — Encode',
    )
    if not output:
        return

    _, extension = os.path.splitext(output)

    if extension.casefold() not in EXTENSIONS_PICTURE:
        showerror(
            title='Save As — Encode',
            message=f'Not a valid extension: {extension}',
            detail=f'Valid extensions: {EXTENSIONS_PICTURE_PRETTY}',
        )
        return

    cipher.text = message
    message = cipher.encrypt()

    # Check the character limit, for Hill cipher :/
    if (cipher.name == crypto.HILL) and (len(message) > Globals.ch_limit):
        showerror(
            title='Encode',
            message='New ciphertext length exceeds the character limit.',
            detail=f'Ciphertext length: {len(message)}',
        )
        return

    message += DELIMITER

    image = Picture.imagedata.copy()

    # Characters -> Bits
    bits = ''.join(format(ord(_), f'0{B}b') for _ in message)

    bits_len = len(bits)

    pixels = list(range(Picture.pixel))

    if seed := ent_rng.get():
        random.seed(seed)
        random.shuffle(pixels)

    i = 0
    for pix, (band, lsb) in itertools.product(pixels, Globals.band_lsb):
        if i >= bits_len:
            break

        val = format(image[pix][band], f'0{B}b')

        pack = val[:B - lsb] + (_ := bits[i:i + lsb]) + val[B - lsb + len(_):]

        # Bits -> File
        image[pix][band] = int(pack, 2)

        i += lsb

    shape = Picture.imagedata.shape[1]
    array = image.reshape((*Picture.dimensions[::-1], shape)).astype(np.uint8)

    try:
        Image.fromarray(array).save(output)
    except (FileNotFoundError, PermissionError) as err:
        showerror(title='Save — Encode', message=str(err))
        return

    VARIABLE_OUTPUT.set(f'"{output}"')

    root.wm_title(root.wm_title().rstrip('*'))

    btn_show['state'] = tk.NORMAL

    showinfo(title='Encode', message='File is encoded.')


def t_decode() -> None:
    """Trigger 'VIRTUAL_EVENT_DECODE'."""
    root.event_generate(VIRTUAL_EVENT_DECODE)


def decode(event: tk.Event) -> None:
    """Extract a hidden message from a stego-object."""
    try:
        cipher = crypto.ciphers[box_ciphers.get()](ent_key.get())
    except ValueError as err:
        showerror(title='Decode', message=str(err))
        return

    output = asksaveasfilename(
        confirmoverwrite=True,
        defaultextension=EXTENSIONS_MESSAGE[0],
        filetypes=[('Text Documents', EXTENSIONS_MESSAGE)],
        initialfile=f'{Picture.filename}-decoded',
        title='Save As — Decode',
    )
    if not output:
        return

    _, extension = os.path.splitext(output)

    if extension.casefold() not in EXTENSIONS_MESSAGE:
        showerror(
            title='Save As — Decode',
            message=f'Not a valid extension: {extension}',
            detail=f'Valid extensions: {EXTENSIONS_MESSAGE_PRETTY}',
        )
        return

    pixels = list(range(Picture.pixel))

    if seed := ent_rng.get():
        random.seed(seed)
        random.shuffle(pixels)

    bits = ''
    message = ''
    for pix, (band, lsb) in itertools.product(pixels, Globals.band_lsb):
        if message.endswith(DELIMITER):
            break

        # File -> Bits
        bits += format(Picture.imagedata[pix][band], f'0{B}b')[-lsb:]

        if len(bits) >= B:
            # Bits -> Characters
            message += chr(int(bits[:B], 2))
            bits = bits[B:]

    if DELIMITER not in message:
        showwarning(title='Decode', message='No hidden message found.')
        return

    message = message.removesuffix(DELIMITER)

    cipher.text = message
    message = cipher.decrypt()

    try:
        with open(output, 'w', encoding='utf-8') as out:
            out.write(message)
    except (FileNotFoundError, PermissionError) as err:
        showerror(title='Save — Decode', message=str(err))
        return

    VARIABLE_OUTPUT.set(f'"{output}"')

    root.wm_title(root.wm_title().rstrip('*'))

    btn_show['state'] = tk.NORMAL

    showinfo(title='Decode', message='File is decoded.')


def show() -> None:
    """Show a previously encoded/decoded file."""
    try:
        os.startfile(VARIABLE_OUTPUT.get(), operation='open')  # nosec
    except (FileNotFoundError, PermissionError) as err:
        showerror(title='Show', message=str(err))


def properties() -> None:
    """Show image properties."""
    showinfo(title='Image Properties', message='\n'.join(Picture.properties))


def close() -> None:
    """Destroy the main window."""
    if CONFIRM_EXIT == '1':
        yes = askokcancel(
            title='Confirm Exit',
            message='Are you sure you want to exit?',
            detail='(You can change this behaviour in configuration file)',
        )
        if yes:
            root.destroy()
    else:
        root.destroy()


def manipulate(v_event: str) -> None:
    """Use a manipulation by triggering the given virtual event."""
    widget = root.focus_get()

    if not widget:
        return

    widget.event_generate(v_event)


def popup(event: tk.Event) -> None:
    """Context menu."""
    event.widget.focus_set()

    try:
        menu_edit.tk_popup(event.x_root, event.y_root)
    finally:
        menu_edit.grab_release()


def toggle_always_on_top() -> None:
    """Toggle 'Always on Top' state."""
    topmost = root.wm_attributes()[root.wm_attributes().index('-topmost') + 1]
    root.wm_attributes('-topmost', 1 - topmost)


def toggle_transparent() -> None:
    """Toggle 'Transparent' state."""
    alpha = root.wm_attributes()[root.wm_attributes().index('-alpha') + 1]
    root.wm_attributes('-alpha', 1.5 - alpha)


def check_for_updates() -> None:
    """Check for the application updates."""
    try:
        with urlopen(URL_LATEST_VERSION, timeout=10.0) as answer:  # nosec
            latest = urlparse(answer.url).path.rstrip('/').rpartition('/')[-1]
    except URLError as err:
        showerror(title='Update', message=str(err))
    else:
        if __version__ != latest:
            yes = askokcancel(
                title='Update',
                message='Update available. Download now?',
                detail=f'Latest version: {latest}',
                icon='warning',
            )
            if yes:
                webbrowser.open_new_tab(urljoin(URL_ARCHIVE, f'{latest}.zip'))
        else:
            showinfo(title='Update', message='You have the latest version.')


def refresh_1(event: tk.Event) -> None:
    """When a file is opened, this method binds widgets to 'F5' once."""
    if Globals.is_bound:
        return

    Globals.is_bound = True

    menu_file.entryconfigure(MENU_ITEM_INDEX_OPEN_TEXT, state=tk.NORMAL)
    root.bind(VIRTUAL_EVENT_OPEN_TEXT, open_text)
    root.bind(VIRTUAL_EVENT_OPEN_TEXT, refresh, add='+')

    menu_file.entryconfigure(MENU_ITEM_INDEX_IMAGE_PROPERTIES, state=tk.NORMAL)

    menu.entryconfigure(MENU_INDEX_EDIT, state=tk.NORMAL)
    root.bind(VIRTUAL_EVENT_UNDO, refresh)
    root.bind(VIRTUAL_EVENT_REDO, refresh)
    root.bind(VIRTUAL_EVENT_CUT, refresh)
    root.bind(VIRTUAL_EVENT_PASTE, refresh)

    ent_rng['state'] = tk.NORMAL

    box_ciphers['state'] = 'readonly'
    box_ciphers.bind('<<ComboboxSelected>>', refresh)

    ent_key['state'] = tk.NORMAL
    ent_key.bind('<KeyRelease>', refresh)

    stx_message['state'] = tk.NORMAL
    stx_message.bind('<ButtonPress-3>', popup)
    stx_message.bind('<KeyRelease>', refresh)

    for scl in band_scl.values():
        scl['state'] = tk.NORMAL
        scl.bind('<ButtonRelease-1>', refresh)  # Left mouse button release
        scl.bind('<ButtonRelease-2>', refresh)  # Middle mouse button release
        scl.bind('<ButtonRelease-3>', refresh)  # Right mouse button release
        scl.bind('<B1-Motion>', refresh)
        scl.bind('<B2-Motion>', refresh)
        scl.bind('<B3-Motion>', refresh)


def refresh(event: tk.Event) -> None:
    """The ultimate refresh function, aka F5."""
    widget = event.widget

    if widget is not box_ciphers:
        pass
    else:
        ent_key.delete('0', tk.END)
        ent_key['vcmd'] = name_vcmd[box_ciphers.get()]  # Update command

    message = stx_message.get('1.0', tk.END)[:-1]

    key = ent_key.get()

    # Activate/deactivate encode/decode features
    if (not key) and box_ciphers.get():
        root.unbind(VIRTUAL_EVENT_ENCODE)
        root.unbind(VIRTUAL_EVENT_DECODE)
        menu_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.DISABLED)
        menu_file.entryconfigure(MENU_ITEM_INDEX_DECODE, state=tk.DISABLED)
        btn_encode['state'] = tk.DISABLED
        btn_decode['state'] = tk.DISABLED
    else:
        root.bind(VIRTUAL_EVENT_DECODE, decode)
        menu_file.entryconfigure(MENU_ITEM_INDEX_DECODE, state=tk.NORMAL)
        btn_decode['state'] = tk.NORMAL
        if message:
            root.bind(VIRTUAL_EVENT_ENCODE, encode)
            menu_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.NORMAL)
            btn_encode['state'] = tk.NORMAL
        else:
            root.unbind(VIRTUAL_EVENT_ENCODE)
            menu_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.DISABLED)
            btn_encode['state'] = tk.DISABLED

    band_lsb = {
        band: int(lsb)
        for band, scl in band_scl.items() if (lsb := scl.get()) != 0
    }

    if widget not in band_scl.values():
        pass
    else:
        if len(band_lsb) != 0:
            # n-LSB warning?
            widget['fg'] = RED if (widget.get() > 3) else BLACK
        # Fix n-LSB
        else:
            widget['fg'] = BLACK
            widget.set(1)
            band_lsb = {list(band_scl.values()).index(widget): 1}

    ch_limit = ((Picture.pixel * sum(band_lsb.values())) // B) - len(DELIMITER)

    if len(message) > ch_limit:
        # Delete excess message
        stx_message.delete('1.0', tk.END)
        stx_message.insert('1.0', message[:ch_limit])

    ch_left = ch_limit - len(stx_message.get('1.0', tk.END)[:-1])

    region_1_1['text'] = f'{ch_left}/{ch_limit}'

    if event.char in ['']:
        pass
    else:
        if (widget is stx_message) or (ch_left == 0):
            # Scroll such that the character at 'INSERT' index is visible
            stx_message.see(stx_message.index(tk.INSERT))

    Globals.band_lsb = tuple(band_lsb.items())

    Globals.ch_limit = ch_limit


def exception(*args) -> None:
    """Report callback exception."""
    logging.critical(args, exc_info=(args[0], args[1], args[2]))
    showerror(
        title='Fatal',
        message=f'An unhandled exception has occurred: {args}',
        detail='(The application will now exit)',
    )
    sys.exit(-1)  # This line of code is important!


sys.excepthook = exception

#################
# DPI AWARENESS #
#################
PROCESS_PER_MONITOR_DPI_AWARE = 2
PROCESS_DPI_AWARENESS = PROCESS_PER_MONITOR_DPI_AWARE

windll.shcore.SetProcessDpiAwareness(PROCESS_DPI_AWARENESS)

###################
# /!\ LOGGING /!\ #
###################
try:
    logging.basicConfig(
        filename=os.path.join(os.path.dirname(__file__), 'sten.log'),
        filemode='a',
        format='\n%(levelname)s %(asctime)s %(message)s\n',
        datefmt='%m/%d/%Y %I:%M %p',
        level=logging.WARNING,
    )
except PermissionError as ex:
    showwarning(title='Log', message=str(ex))

###############
# Window Root #
###############
root = tk.Tk()
root.pack_propagate(True)

root.report_callback_exception = exception

root.wm_protocol('WM_DELETE_WINDOW', close)

root.wm_iconphoto(True, tk.PhotoImage(data=data64.ICON_DATA_STEN))
windll.shell32.SetCurrentProcessExplicitAppUserModelID('gibberish')  # Taskbar

root.wm_title(f'Sten {__version__}')

SCREEN_W = root.winfo_screenwidth()
SCREEN_H = root.winfo_screenheight()

WINDOW_W = 1000
WINDOW_H = 550
WINDOW_W = SCREEN_W if (SCREEN_W < WINDOW_W) else WINDOW_W
WINDOW_H = SCREEN_H if (SCREEN_H < WINDOW_H) else WINDOW_H

CENTER_X = (SCREEN_W // 2) - (WINDOW_W // 2)
CENTER_Y = (SCREEN_H // 2) - (WINDOW_H // 2)

root.wm_resizable(width=True, height=True)
root.wm_minsize(width=WINDOW_W, height=WINDOW_H)
root.wm_geometry(f'{WINDOW_W}x{WINDOW_H}-{CENTER_X}-{CENTER_Y}')

font = Font(family='Consolas', size=9, weight='normal')
root.option_add(pattern='*Font', value=font)

#############
# Menu Root #
#############
menu = tk.Menu(root, tearoff=False)
root.configure(menu=menu)

MENU_INDEX_EDIT = 1

#############
# Menu File #
#############
menu_file = tk.Menu(menu, tearoff=False)
menu.add_cascade(label='File', menu=menu_file, state=tk.NORMAL, underline=0)

MENU_ITEM_INDEX_OPEN_TEXT = 1
MENU_ITEM_INDEX_ENCODE = 3
MENU_ITEM_INDEX_DECODE = 4
MENU_ITEM_INDEX_IMAGE_PROPERTIES = 6

ICON_OPEN = tk.PhotoImage(data=data64.ICON_DATA_OPEN)
ICON_ENCODE = tk.PhotoImage(data=data64.ICON_DATA_ENCODE)
ICON_DECODE = tk.PhotoImage(data=data64.ICON_DATA_DECODE)
ICON_IMAGE_PROPERTIES = tk.PhotoImage(data=data64.ICON_DATA_IMAGE_PROPERTIES)

# Stay away from <Control-Key-o> key sequence! Read [28]:
# https://www.tcl.tk/man/tcl/TkCmd/text.html#M192
root.event_add(VIRTUAL_EVENT_OPEN, *SEQUENCE_OPEN)
root.event_add(VIRTUAL_EVENT_ENCODE, *SEQUENCE_ENCODE)
root.event_add(VIRTUAL_EVENT_DECODE, *SEQUENCE_DECODE)

menu_file.add_command(
    accelerator=SHORTCUT_OPEN,
    command=t_open_,
    compound=tk.LEFT,
    image=ICON_OPEN,
    label='Open...',
    state=tk.NORMAL,
    underline=3,
)
root.bind(VIRTUAL_EVENT_OPEN, open_)
root.bind(VIRTUAL_EVENT_OPEN, refresh_1, add='+')
root.bind(VIRTUAL_EVENT_OPEN, refresh, add='+')
menu_file.add_command(
    command=t_open_text,
    label='Open Text...',
    state=tk.DISABLED,
    underline=5,
)
menu_file.add_separator()
menu_file.add_command(
    accelerator=SHORTCUT_ENCODE,
    command=t_encode,
    compound=tk.LEFT,
    image=ICON_ENCODE,
    label='Encode...',
    state=tk.DISABLED,
    underline=0,
)
menu_file.add_command(
    accelerator=SHORTCUT_DECODE,
    command=t_decode,
    compound=tk.LEFT,
    image=ICON_DECODE,
    label='Decode...',
    state=tk.DISABLED,
    underline=0,
)
menu_file.add_separator()
menu_file.add_command(
    command=properties,
    compound=tk.LEFT,
    image=ICON_IMAGE_PROPERTIES,
    label='Image Properties',
    state=tk.DISABLED,
    underline=7,
)
menu_file.add_separator()
menu_file.add_command(
    command=close,
    label='Exit',
    state=tk.NORMAL,
    underline=1,
)

#############
# Menu Edit #
#############
menu_edit = tk.Menu(menu, tearoff=False)
menu.add_cascade(label='Edit', menu=menu_edit, state=tk.DISABLED, underline=0)

ICON_UNDO = tk.PhotoImage(data=data64.ICON_DATA_UNDO)
ICON_REDO = tk.PhotoImage(data=data64.ICON_DATA_REDO)
ICON_CUT = tk.PhotoImage(data=data64.ICON_DATA_CUT)
ICON_COPY = tk.PhotoImage(data=data64.ICON_DATA_COPY)
ICON_PASTE = tk.PhotoImage(data=data64.ICON_DATA_PASTE)
ICON_SELECT_ALL = tk.PhotoImage(data=data64.ICON_DATA_SELECT_ALL)

# Remove all defaults...
root.event_delete(VIRTUAL_EVENT_UNDO)
root.event_delete(VIRTUAL_EVENT_REDO)
root.event_delete(VIRTUAL_EVENT_CUT)
root.event_delete(VIRTUAL_EVENT_COPY)
root.event_delete(VIRTUAL_EVENT_PASTE)
root.event_delete(VIRTUAL_EVENT_SELECT_ALL)

# ...then add new ones
root.event_add(VIRTUAL_EVENT_UNDO, *SEQUENCE_UNDO)
root.event_add(VIRTUAL_EVENT_REDO, *SEQUENCE_REDO)
root.event_add(VIRTUAL_EVENT_CUT, *SEQUENCE_CUT)
root.event_add(VIRTUAL_EVENT_COPY, *SEQUENCE_COPY)
root.event_add(VIRTUAL_EVENT_PASTE, *SEQUENCE_PASTE)
root.event_add(VIRTUAL_EVENT_SELECT_ALL, *SEQUENCE_SELECT_ALL)

menu_edit.add_command(
    accelerator=SHORTCUT_UNDO,
    command=lambda: manipulate(VIRTUAL_EVENT_UNDO),
    compound=tk.LEFT,
    image=ICON_UNDO,
    label='Undo',
    state=tk.NORMAL,
    underline=0,
)
menu_edit.add_command(
    accelerator=SHORTCUT_REDO,
    command=lambda: manipulate(VIRTUAL_EVENT_REDO),
    compound=tk.LEFT,
    image=ICON_REDO,
    label='Redo',
    state=tk.NORMAL,
    underline=0,
)
menu_edit.add_separator()
menu_edit.add_command(
    accelerator=SHORTCUT_CUT,
    command=lambda: manipulate(VIRTUAL_EVENT_CUT),
    compound=tk.LEFT,
    image=ICON_CUT,
    label='Cut',
    state=tk.NORMAL,
    underline=2,
)
menu_edit.add_command(
    accelerator=SHORTCUT_COPY,
    command=lambda: manipulate(VIRTUAL_EVENT_COPY),
    compound=tk.LEFT,
    image=ICON_COPY,
    label='Copy',
    state=tk.NORMAL,
    underline=0,
)
menu_edit.add_command(
    accelerator=SHORTCUT_PASTE,
    command=lambda: manipulate(VIRTUAL_EVENT_PASTE),
    compound=tk.LEFT,
    image=ICON_PASTE,
    label='Paste',
    state=tk.NORMAL,
    underline=0,
)
menu_edit.add_separator()
menu_edit.add_command(
    accelerator=SHORTCUT_SELECT_ALL,
    command=lambda: manipulate(VIRTUAL_EVENT_SELECT_ALL),
    compound=tk.LEFT,
    image=ICON_SELECT_ALL,
    label='Select All',
    state=tk.NORMAL,
    underline=7,
)

###############
# Menu Window #
###############
menu_win = tk.Menu(menu, tearoff=False)
menu.add_cascade(label='Window', menu=menu_win, state=tk.NORMAL, underline=0)

menu_win.add_checkbutton(
    command=toggle_always_on_top,
    label='Always on Top',
    state=tk.NORMAL,
    underline=0,
)
menu_win.add_checkbutton(
    command=toggle_transparent,
    label='Transparent',
    state=tk.NORMAL,
    underline=0,
)

#############
# Menu Help #
#############
menu_help = tk.Menu(menu, tearoff=False)
menu.add_cascade(label='Help', menu=menu_help, state=tk.NORMAL, underline=0)

ICON_ABOUT = tk.PhotoImage(data=data64.ICON_DATA_ABOUT)

menu_help.add_command(
    command=lambda: webbrowser.open_new_tab(URL),
    label='GitHub...',
    state=tk.NORMAL,
    underline=0,
)
menu_help.add_separator()
menu_help.add_command(
    command=check_for_updates,
    label='Check for Updates...',
    state=tk.NORMAL,
    underline=10,
)
menu_help.add_command(
    command=lambda: webbrowser.open_new_tab(URL_CHANGELOG),
    label='Changelog...',
    state=tk.NORMAL,
    underline=6,
)
menu_help.add_command(
    command=lambda: showinfo(title='About Sten', message=__doc__),
    compound=tk.LEFT,
    image=ICON_ABOUT,
    label='About',
    state=tk.NORMAL,
    underline=0,
)

###############
# Region Root #
###############
region = tk.Frame(
    root,
    bd=0,
    bg=BLACK,
    relief=tk.FLAT,
)
region.grid_propagate(True)
region.grid_rowconfigure(index=0, weight=0)
region.grid_rowconfigure(index=1, weight=0)
region.grid_rowconfigure(index=2, weight=0)
region.grid_rowconfigure(index=3, weight=1)
region.grid_columnconfigure(index=0, weight=0)
region.grid_columnconfigure(index=1, weight=1)
region.pack_configure(expand=True, fill=tk.BOTH, side=tk.TOP)

#################
# Region (0, 0) #
#################
region_0_0 = tk.Frame(
    region,
    bd=2,
    bg=BLACK,
    relief=tk.RIDGE,
)
region_0_0.pack_propagate(True)
region_0_0.grid_configure(
    row=0, column=0, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)

#################
# Button Encode #
#################
btn_encode = tk.Button(
    region_0_0,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=5,
    bg=WHITE,
    command=t_encode,
    compound=tk.LEFT,
    fg=BLACK,
    image=ICON_ENCODE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    text='Encode',
)
btn_encode.pack_configure(
    expand=True, fill=tk.BOTH, side=tk.LEFT, padx=PAD_X, pady=PAD_Y
)
Hovertip(
    btn_encode, text=f'[{SHORTCUT_ENCODE}]\n{encode.__doc__}', hover_delay=750
)

#################
# Button Decode #
#################
btn_decode = tk.Button(
    region_0_0,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=5,
    bg=WHITE,
    command=t_decode,
    compound=tk.LEFT,
    fg=BLACK,
    image=ICON_DECODE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    text='Decode',
)
btn_decode.pack_configure(
    expand=True, fill=tk.BOTH, side=tk.LEFT, padx=PAD_X, pady=PAD_Y
)
Hovertip(
    btn_decode, text=f'[{SHORTCUT_DECODE}]\n{decode.__doc__}', hover_delay=750
)

#################
# Region (0, 1) #
#################
region_0_1 = tk.Frame(
    region,
    bd=2,
    bg=BLACK,
    relief=tk.RIDGE,
)
region_0_1.grid_propagate(True)
region_0_1.grid_rowconfigure(index=0, weight=1)
region_0_1.grid_rowconfigure(index=1, weight=1)
region_0_1.grid_columnconfigure(index=0, weight=0)
region_0_1.grid_columnconfigure(index=1, weight=1)
region_0_1.grid_columnconfigure(index=2, weight=0)
region_0_1.grid_configure(
    row=0, column=1, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)

#######################
# Section Opened File #
#######################
tk.Label(
    region_0_1,
    anchor=tk.CENTER,
    bd=0,
    bg=BLACK,
    fg=WHITE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    text='Opened',
).grid_configure(row=0, column=0, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW)
tk.Entry(
    region_0_1,
    bd=0,
    fg=BLACK,
    readonlybackground=WHITE,
    relief=tk.FLAT,
    state='readonly',
    textvariable=(VARIABLE_OPENED := tk.StringVar()),
).grid_configure(row=0, column=1, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW)
btn_open = tk.Button(
    region_0_1,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=5,
    bg=WHITE,
    command=t_open_,
    fg=BLACK,
    relief=tk.FLAT,
    state=tk.NORMAL,
    text='Open',
)
btn_open.grid_configure(
    row=0, column=2, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)
Hovertip(
    btn_open, text=f'[{SHORTCUT_OPEN}]\n{open_.__doc__}', hover_delay=750
)

#######################
# Section Output File #
#######################
tk.Label(
    region_0_1,
    anchor=tk.CENTER,
    bd=0,
    bg=BLACK,
    fg=WHITE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    text='Output',
).grid_configure(row=1, column=0, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW)
tk.Entry(
    region_0_1,
    bd=0,
    fg=BLACK,
    readonlybackground=WHITE,
    relief=tk.FLAT,
    state='readonly',
    textvariable=(VARIABLE_OUTPUT := tk.StringVar()),
).grid_configure(row=1, column=1, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW)
btn_show = tk.Button(
    region_0_1,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=5,
    bg=WHITE,
    command=show,
    fg=BLACK,
    relief=tk.FLAT,
    state=tk.DISABLED,
    text='Show',
)
btn_show.grid_configure(
    row=1, column=2, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)
Hovertip(btn_show, text=show.__doc__, hover_delay=750)

#################
# Region (1, 0) #
#################
region_1_0 = tk.LabelFrame(
    region,
    bd=2,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='PRNG',
)
region_1_0.pack_propagate(True)
region_1_0.grid_configure(
    row=1, column=0, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)

#############
# PRNG Seed #
#############
ent_rng = tk.Entry(
    region_1_0,
    bd=0,
    bg=WHITE,
    fg=BLACK,
    relief=tk.FLAT,
    show=PRNG_SEED_MASK,
    state=tk.DISABLED,
)
ent_rng.bind(VIRTUAL_EVENT_PASTE, lambda e: 'break')  # No paste
ent_rng.pack_configure(
    expand=True, fill=tk.BOTH, ipady=10.0, side=tk.TOP, padx=PAD_X, pady=PAD_Y
)
Hovertip(ent_rng, text='Pseudo-random number generator seed.', hover_delay=750)

#################
# Region (2, 0) #
#################
region_2_0 = tk.LabelFrame(
    region,
    bd=2,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='Encryption',
)
region_2_0.pack_propagate(True)
region_2_0.grid_configure(
    row=2, column=0, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)

###########
# Ciphers #
###########
box_ciphers = Combobox(
    region_2_0,
    background=WHITE,
    foreground=BLACK,
    state=tk.DISABLED,
    values=list(crypto.ciphers),
)
box_ciphers.current(1)
box_ciphers.pack_configure(
    expand=True, fill=tk.BOTH, ipady=7.5, side=tk.TOP, padx=PAD_X, pady=PAD_Y
)
Hovertip(box_ciphers, text=crypto.__doc__, hover_delay=750)

##############
# Cipher Key #
##############
name_vcmd = {
    name: (root.register(cipher.validate), *cipher.code)
    for name, cipher in crypto.ciphers.items()
}

ent_key = tk.Entry(
    region_2_0,
    bd=0,
    bg=WHITE,
    fg=BLACK,
    relief=tk.FLAT,
    show=CIPHER_KEY_MASK,
    state=tk.DISABLED,
    validate='key',
    validatecommand=name_vcmd[box_ciphers.get()],
)
ent_key.bind(VIRTUAL_EVENT_PASTE, lambda e: 'break')  # No paste
ent_key.pack_configure(
    expand=True, fill=tk.BOTH, ipady=10.0, side=tk.TOP, padx=PAD_X, pady=PAD_Y
)
Hovertip(ent_key, text='Cipher key.', hover_delay=750)

#################
# Region (3, 0) #
#################
region_3_0 = tk.LabelFrame(
    region,
    bd=2,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='n-LSB',
)
region_3_0.pack_propagate(True)
region_3_0.grid_configure(
    row=3, column=0, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)

#################
# Section n-LSB #
#################
band_scl = {
    0: tk.Scale(region_3_0, fg=BLACK, from_=B, to=0, troughcolor=RED),
    1: tk.Scale(region_3_0, fg=BLACK, from_=B, to=0, troughcolor=GREEN),
    2: tk.Scale(region_3_0, fg=BLACK, from_=B, to=0, troughcolor=BLUE),
}  # Stick with this order!

for scale in band_scl.values():
    scale.set(1)
    scale.configure(
        bd=2,
        relief=tk.FLAT,
        sliderlength=50,
        sliderrelief=tk.RAISED,
        state=tk.DISABLED,
    )
    scale.pack_configure(
        expand=True, fill=tk.BOTH, side=tk.LEFT, padx=PAD_X, pady=PAD_Y
    )

#################
# Region (1, 1) #
#################
region_1_1 = tk.LabelFrame(
    region,
    bd=2,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.SE,
    relief=tk.RIDGE,
    text='-/-',
)
region_1_1.pack_propagate(True)
region_1_1.grid_configure(
    row=1, rowspan=3, column=1, padx=PAD_X, pady=PAD_Y, sticky=tk.NSEW
)

###################
# Section Message #
###################
stx_message = ScrolledText(
    region_1_1,
    bd=0,
    bg=WHITE,
    fg=BLACK,
    relief=tk.FLAT,
    state=tk.DISABLED,
    tabs=1,
    undo=True,
    wrap='char',
)
stx_message.pack_configure(
    expand=True, fill=tk.BOTH, side=tk.TOP, padx=PAD_X, pady=PAD_Y
)

if __name__ == '__main__':
    root.mainloop()
