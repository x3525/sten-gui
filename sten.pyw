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

import collections
import ctypes
import dataclasses
import logging
import math
import os
import random
import string
import sys
import tkinter as tk
import warnings
import webbrowser
from contextlib import suppress
from idlelib.tooltip import Hovertip  # type: ignore
from itertools import compress, product
from tkinter import ttk
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
from typing import NoReturn

import numpy as np
from PIL import Image, UnidentifiedImageError
from numpy.typing import NDArray

import crypto
from consts import *
from db import Db
from error import CryptoErrorGroup
from icons import *
from utils import nonascii, splitext

# Turn matching warnings into exceptions
warnings.simplefilter('error', Image.DecompressionBombWarning)


@dataclasses.dataclass
class Globals:
    """Global "control" variables for the internal module."""

    i_lsb: tuple[tuple[int, int], ...]
    limit: int


@dataclasses.dataclass
class Picture:
    """Image properties of a previously opened picture file."""

    pixel: int
    imagedata: NDArray
    dimensions: tuple[int, int]
    mode: str

    filename: str
    extension: str

    properties: tuple[str, ...]


def openasfile(event: tk.Event) -> str | None:
    """Open a picture file."""
    retry = True
    while retry:
        file = askopenfilename(
            filetypes=[('Picture Files', EXTENSIONS_PICTURE)],
            initialdir='~',
            title='Open File',
        )

        if not file:
            break

        filename, extension = splitext(file)

        if extension.casefold() not in EXTENSIONS_PICTURE:
            retry = askretrycancel(
                title='Open File',
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
                OSError,
                UnidentifiedImageError,
                Image.DecompressionBombError, Image.DecompressionBombWarning,
        ) as err:
            retry = askretrycancel(title='Open File', message=str(err))
            continue

        if mode not in MODES_PICTURE:
            retry = askretrycancel(
                title='Open File',
                message=f'Mode not supported: {mode}',
                detail=f'Supported modes: {MODES_PICTURE_PRETTY}',
            )
            continue

        if pixel < MIN_PIXEL:
            retry = askretrycancel(
                title='Open File',
                message=f'Need minimum {MIN_PIXEL} pixels.',
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

        capacity = (Picture.pixel * RGB) - len(DELIMITER)

        Picture.properties = (
            f'Capacity: {capacity} characters',
            f'Width: {width} pixels',
            f'Height: {height} pixels',
            f'Bit depth: {B * len(Picture.mode)} ({Picture.mode})',
        )

        Var_opened.set(file)
        Var_output.set('')

        B_show['state'] = tk.DISABLED

        return None

    return 'break'  # No more event processing for "V_EVENT_OPEN_FILE"


def openastext(event: tk.Event) -> str | None:
    """Read the contents of a file as text."""
    retry = True
    while retry:
        file = askopenfilename(
            filetypes=[('All Files', EXTENSIONS_ALL)],
            initialdir='~',
            title='Open Text',
        )

        if not file:
            break

        try:
            with open(file, encoding='ascii', errors='ignore') as text:
                notebook['encode'].delete('1.0', tk.END)
                notebook['encode'].insert('1.0', text.read())
        except OSError as err:
            retry = askretrycancel(title='Open Text', message=str(err))
            continue
        else:
            N_stego.select(notebook['encode'])
            return None

    return 'break'


def encode(event: tk.Event):
    """Create a stego-object."""
    cipher_name, key = X_ciphers.get(), E_key.get()

    if (not key) and cipher_name:
        return

    message = notebook['encode'].get('1.0', tk.END)[:-1]

    if not message:
        return

    if char := nonascii(message):
        showerror(
            title='Encode',
            message='Message contains a non-ASCII character.',
            detail=f'Character: {char}',
        )
        return

    try:
        cipher = crypto.ciphers[cipher_name](key, message)
    except CryptoErrorGroup as err:
        showerror(title='Encode', message=str(err))
        return

    message = cipher.encrypt()

    # Check the character limit, for Hill cipher :/
    if (cipher.name == crypto.Hill.name) and (len(message) > Globals.limit):
        showerror(
            title='Encode',
            message='Cipher text length exceeds the character limit.',
        )
        return

    if DELIMITER in message:
        if not askokcancel(
                title='Encode',
                message='Some data will be lost!',
                detail='(Message will contain the delimiter)',
                icon='warning',
        ):
            return

    output = asksaveasfilename(
        confirmoverwrite=True,
        defaultextension=Picture.extension,
        filetypes=[('Picture Files', EXTENSIONS_PICTURE)],
        initialfile=f'{Picture.filename}-encoded',
        title='Save As',
    )
    if not output:
        return

    _, extension = splitext(output)

    if extension.casefold() not in EXTENSIONS_PICTURE:
        showerror(
            title='Save As',
            message=f'Not a valid extension: {extension}',
            detail=f'Valid extensions: {EXTENSIONS_PICTURE_PRETTY}',
        )
        return

    message += DELIMITER

    image = Picture.imagedata.copy()

    # Characters -> Bits
    bits = ''.join(format(ord(c), f'0{B}b') for c in message)

    bits_length = len(bits)

    pixels = list(range(Picture.pixel))

    if seed := E_prng.get():
        random.seed(seed)
        random.shuffle(pixels)

    i = 0

    for pix, (band, lsb) in product(pixels, Globals.i_lsb):
        if i >= bits_length:
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
    except OSError as err:
        showerror(title='Save As', message=str(err))
        return

    Var_output.set(output)

    B_show['state'] = tk.NORMAL

    showinfo(title='Encode', message='File is encoded!')


def decode(event: tk.Event):
    """Extract a hidden message from a stego-object."""
    cipher_name, key = X_ciphers.get(), E_key.get()

    if (not key) and cipher_name:
        return

    try:
        cipher = crypto.ciphers[cipher_name](key)
    except CryptoErrorGroup as err:
        showerror(title='Decode', message=str(err))
        return

    pixels = list(range(Picture.pixel))

    if seed := E_prng.get():
        random.seed(seed)
        random.shuffle(pixels)

    for i_lsb in possibilities if config['brute'].get() else (Globals.i_lsb,):
        bits, message = '', ''

        for pix, (band, lsb) in product(pixels, i_lsb):
            if message.endswith(DELIMITER):
                break  # No need to go any further

            # File -> Bits
            bits += format(Picture.imagedata[pix][band], f'0{B}b')[-lsb:]

            if len(bits) >= B:
                # Bits -> Characters
                message += chr(int(bits[:B], 2))
                bits = bits[B:]

        if message.endswith(DELIMITER):
            break
    else:
        showwarning(title='Decode', message='No hidden message found.')
        return

    if nonascii(message):
        showerror(
            title='Decode',
            message='Message contains a non-ASCII character.',
            detail='Are you sure this message was created using Sten?',
        )
        return

    message = message.removesuffix(DELIMITER)

    cipher.txt = message
    message = cipher.decrypt()

    Var_output.set('')

    B_show['state'] = tk.DISABLED

    notebook['decode'].delete('1.0', tk.END)
    notebook['decode'].insert('1.0', message)

    N_stego.select(notebook['decode'])

    showinfo(title='Decode', message='File is decoded!')


def show():
    """Show a previously created stego-object."""
    try:
        os.startfile(Var_output.get(), operation='open')  # nosec
    except OSError as err:
        showerror(title='Show', message=str(err))


def preferences():
    """Show preferences."""
    toplevel = tk.Toplevel(root)

    toplevel.grab_set()  # Direct all events to this Toplevel

    toplevel.pack_propagate(True)

    toplevel.wm_title('Preferences')

    tk.Checkbutton(
        toplevel,
        anchor=tk.W,
        text='Confirm before exiting the program',
        variable=config['confirm'],
    ).pack_configure(expand=True, fill=tk.BOTH, side=tk.TOP)
    tk.Checkbutton(
        toplevel,
        anchor=tk.W,
        text='Use brute force technique to decode',
        variable=config['brute'],
    ).pack_configure(expand=True, fill=tk.BOTH, side=tk.TOP)


def properties():
    """Show image properties."""
    showinfo(title='Image Properties', message='\n'.join(Picture.properties))


def close():
    """Destroy the main window."""
    if config['confirm'].get():
        if not askokcancel(
                title='Confirm Exit',
                message='Are you sure you want to exit?',
        ):
            return
    database.truncate()
    database.insert([(row,) for row, var in config.items() if var.get()])
    root.destroy()


def manipulate(v_event: str):
    """Use a manipulation by triggering the given virtual event."""
    widget = root.focus_get()

    if not widget:
        return
    if widget is notebook['decode']:
        return

    widget.event_generate(v_event)


def popup(event: tk.Event):
    """Show context menu."""
    event.widget.focus_set()

    try:
        M_edit.tk_popup(event.x_root, event.y_root)
    finally:
        M_edit.grab_release()


def always():
    """Toggle "Always on Top" state."""
    topmost = root.wm_attributes()[root.wm_attributes().index('-topmost') + 1]
    root.wm_attributes('-topmost', 1 - topmost)


def transparent():
    """Toggle "Transparent" state."""
    alpha = root.wm_attributes()[root.wm_attributes().index('-alpha') + 1]
    root.wm_attributes('-alpha', 1.5 - alpha)


def activate(event: tk.Event):
    """When a file is opened, this method binds widgets to "refresh" once."""
    # Unbind to prevent reactivation
    root.bind(V_EVENT_OPEN_FILE, openasfile)
    root.bind(V_EVENT_OPEN_FILE, refresh, add='+')

    M_file.entryconfigure(MENU_ITEM_INDEX_OPEN_TEXT, state=tk.NORMAL)
    root.bind(V_EVENT_OPEN_TEXT, openastext)
    root.bind(V_EVENT_OPEN_TEXT, refresh, add='+')

    M_file.entryconfigure(MENU_ITEM_INDEX_IMAGE_PROPERTIES, state=tk.NORMAL)

    menu.entryconfigure(MENU_INDEX_EDIT, state=tk.NORMAL)
    root.bind(V_EVENT_UNDO, refresh)
    root.bind(V_EVENT_REDO, refresh)
    root.bind(V_EVENT_CUT, refresh)
    root.bind(V_EVENT_PASTE, refresh)

    E_prng['state'] = tk.NORMAL

    X_ciphers['state'] = 'readonly'
    X_ciphers.bind('<<ComboboxSelected>>', refresh)

    E_key['state'] = tk.NORMAL
    E_key.bind('<KeyRelease>', refresh)

    N_stego.tab(notebook['encode'], state=tk.NORMAL)
    N_stego.tab(notebook['decode'], state=tk.NORMAL)

    N_stego.select(notebook['encode'])

    notebook['encode'].bind('<ButtonPress-3>', popup)
    notebook['encode'].bind('<KeyRelease>', refresh)
    notebook['decode'].bind('<KeyPress>', lambda e: 'break')

    for scl in scales:
        scl['state'] = tk.NORMAL
        scl.bind('<ButtonRelease-1>', refresh)  # Left mouse button release
        scl.bind('<ButtonRelease-2>', refresh)  # Middle mouse button release
        scl.bind('<ButtonRelease-3>', refresh)  # Right mouse button release
        scl.bind('<B1-Motion>', refresh)
        scl.bind('<B2-Motion>', refresh)
        scl.bind('<B3-Motion>', refresh)


def refresh(event: tk.Event):
    """The ultimate refresh function."""
    widget = event.widget

    ciphername = X_ciphers.get()

    if widget is not X_ciphers:
        pass
    else:
        E_key.delete('0', tk.END)
        E_key['vcmd'] = name_vcmd[ciphername]  # Update validate command

    message = notebook['encode'].get('1.0', tk.END)[:-1]

    key = E_key.get()

    # Activate/deactivate encode/decode features
    if (not key) and ciphername:
        root.unbind(V_EVENT_ENCODE)
        root.unbind(V_EVENT_DECODE)
        M_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.DISABLED)
        M_file.entryconfigure(MENU_ITEM_INDEX_DECODE, state=tk.DISABLED)
        B_encode['state'] = tk.DISABLED
        B_decode['state'] = tk.DISABLED
    else:
        root.bind(V_EVENT_DECODE, decode)
        M_file.entryconfigure(MENU_ITEM_INDEX_DECODE, state=tk.NORMAL)
        B_decode['state'] = tk.NORMAL
        if message:
            root.bind(V_EVENT_ENCODE, encode)
            M_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.NORMAL)
            B_encode['state'] = tk.NORMAL
        else:
            root.unbind(V_EVENT_ENCODE)
            M_file.entryconfigure(MENU_ITEM_INDEX_ENCODE, state=tk.DISABLED)
            B_encode['state'] = tk.DISABLED

    i_lsb = {
        band: lsb
        for band, scl in enumerate(scales) if (lsb := int(scl.get())) != 0
    }

    if widget not in scales:
        pass
    else:
        if len(i_lsb) != 0:
            # LSB warning?
            widget['fg'] = BLACK if (widget.get() < 4) else RED
        # Fix LSB
        else:
            widget['fg'] = BLACK
            widget.set(1)
            i_lsb = {scales.index(widget): 1}

    limit = ((Picture.pixel * sum(i_lsb.values())) // B) - len(DELIMITER)

    if len(message) > limit:
        # Delete excess message
        notebook['encode'].delete('1.0', tk.END)
        notebook['encode'].insert('1.0', message[:limit])

    used = len(notebook['encode'].get('1.0', tk.END)[:-1])

    left = limit - used

    F_book['text'] = template.substitute(used=used, left=left, limit=limit)

    if event.char in ['']:
        pass
    else:
        if (widget is notebook['encode']) or (left == 0):
            # Scroll such that the character at "INSERT" index is visible
            notebook['encode'].see(notebook['encode'].index(tk.INSERT))

    Globals.i_lsb = tuple(i_lsb.items())

    Globals.limit = limit


def exception(*msg) -> NoReturn:
    """Report callback exception."""
    logging.critical(msg, exc_info=(msg[0], msg[1], msg[2]))
    showerror(title='Fatal Error', message=str(msg))
    os._exit(-1)


sys.excepthook = exception

#################
# Dpi Awareness #
#################
PROCESS_PER_MONITOR_DPI_AWARE = 2
PROCESS_DPI_AWARENESS = PROCESS_PER_MONITOR_DPI_AWARE

ctypes.windll.shcore.SetProcessDpiAwareness(PROCESS_DPI_AWARENESS)

###################
# /!\ Logging /!\ #
###################
with suppress(OSError):
    logging.basicConfig(
        filename=os.path.join(os.path.dirname(__file__), 'sten.log'),
        format='\n%(asctime)s',
    )

########
# ROOT #
########
root = tk.Tk()

root.report_callback_exception = exception

root.pack_propagate(True)

root.wm_protocol('WM_DELETE_WINDOW', close)

root.wm_iconphoto(True, tk.PhotoImage(data=IMAGE_DATA_STEN))

ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(' ')

root.wm_title('Sten')

SCREEN_W = root.winfo_screenwidth()
SCREEN_H = root.winfo_screenheight()

WINDOW_W = 1000
WINDOW_H = 550
WINDOW_W = SCREEN_W if (SCREEN_W < WINDOW_W) else WINDOW_W
WINDOW_H = SCREEN_H if (SCREEN_H < WINDOW_H) else WINDOW_H

CENTER_X = (SCREEN_W // 2) - (WINDOW_W // 2)
CENTER_Y = (SCREEN_H // 2) - (WINDOW_H // 2)

root.wm_resizable(True, True)

WINDOW_W_MIN = WINDOW_W // 2
WINDOW_H_MIN = WINDOW_H

root.wm_minsize(WINDOW_W_MIN, WINDOW_H_MIN)

GEOMETRY = f'{WINDOW_W}x{WINDOW_H}-{CENTER_X}-{CENTER_Y}'

root.wm_geometry(GEOMETRY)

font = Font(family='Consolas', size=9, weight='normal')

root.option_add('*Font', font)

style = ttk.Style()

style.configure('.', font=font)  # Ttk widgets only!

########
# Menu #
########
menu = tk.Menu(root, tearoff=False)

root.configure(menu=menu)

MENU_INDEX_EDIT = 1

##############
# Menu: File #
##############
M_file = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='File', menu=M_file, state=tk.NORMAL, underline=0)

MENU_ITEM_INDEX_OPEN_TEXT = 1
MENU_ITEM_INDEX_ENCODE = 3
MENU_ITEM_INDEX_DECODE = 4
MENU_ITEM_INDEX_PREFERENCES = 6
MENU_ITEM_INDEX_IMAGE_PROPERTIES = 7

IMAGE_OPEN_FILE = tk.PhotoImage(data=IMAGE_DATA_OPEN_FILE)
IMAGE_ENCODE = tk.PhotoImage(data=IMAGE_DATA_ENCODE)
IMAGE_DECODE = tk.PhotoImage(data=IMAGE_DATA_DECODE)
IMAGE_PREFERENCES = tk.PhotoImage(data=IMAGE_DATA_PREFERENCES)

# Stay away from <Control-Key-o> key sequence!
root.event_add(V_EVENT_OPEN_FILE, *SEQUENCE_OPEN_FILE)
root.event_add(V_EVENT_ENCODE, *SEQUENCE_ENCODE)
root.event_add(V_EVENT_DECODE, *SEQUENCE_DECODE)

M_file.add_command(
    accelerator=SHORTCUT_OPEN_FILE,
    command=lambda: root.event_generate(V_EVENT_OPEN_FILE),
    compound=tk.LEFT,
    image=IMAGE_OPEN_FILE,
    label='Open File',
    state=tk.NORMAL,
    underline=3,
)

root.bind(V_EVENT_OPEN_FILE, openasfile)
root.bind(V_EVENT_OPEN_FILE, activate, add='+')
root.bind(V_EVENT_OPEN_FILE, refresh, add='+')

M_file.add_command(
    command=lambda: root.event_generate(V_EVENT_OPEN_TEXT),
    label='Open Text',
    state=tk.DISABLED,
    underline=5,
)

M_file.add_separator()

M_file.add_command(
    accelerator=SHORTCUT_ENCODE,
    command=lambda: root.event_generate(V_EVENT_ENCODE),
    compound=tk.LEFT,
    image=IMAGE_ENCODE,
    label='Encode',
    state=tk.DISABLED,
    underline=0,
)
M_file.add_command(
    accelerator=SHORTCUT_DECODE,
    command=lambda: root.event_generate(V_EVENT_DECODE),
    compound=tk.LEFT,
    image=IMAGE_DECODE,
    label='Decode',
    state=tk.DISABLED,
    underline=0,
)

M_file.add_separator()

M_file.add_command(
    command=preferences,
    compound=tk.LEFT,
    image=IMAGE_PREFERENCES,
    label='Preferences',
    state=tk.NORMAL,
    underline=0,
)
M_file.add_command(
    command=properties,
    label='Image Properties',
    state=tk.DISABLED,
    underline=7,
)

M_file.add_separator()

M_file.add_command(
    command=close,
    label='Exit',
    state=tk.NORMAL,
    underline=1,
)

##############
# Menu: Edit #
##############
M_edit = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='Edit', menu=M_edit, state=tk.DISABLED, underline=0)

IMAGE_UNDO = tk.PhotoImage(data=IMAGE_DATA_UNDO)
IMAGE_REDO = tk.PhotoImage(data=IMAGE_DATA_REDO)
IMAGE_CUT = tk.PhotoImage(data=IMAGE_DATA_CUT)
IMAGE_COPY = tk.PhotoImage(data=IMAGE_DATA_COPY)
IMAGE_PASTE = tk.PhotoImage(data=IMAGE_DATA_PASTE)
IMAGE_SELECT_ALL = tk.PhotoImage(data=IMAGE_DATA_SELECT_ALL)

# Delete all defaults...
root.event_delete(V_EVENT_UNDO)
root.event_delete(V_EVENT_REDO)
root.event_delete(V_EVENT_CUT)
root.event_delete(V_EVENT_COPY)
root.event_delete(V_EVENT_PASTE)
root.event_delete(V_EVENT_SELECT_ALL)

# ...then add new ones
root.event_add(V_EVENT_UNDO, *SEQUENCE_UNDO)
root.event_add(V_EVENT_REDO, *SEQUENCE_REDO)
root.event_add(V_EVENT_CUT, *SEQUENCE_CUT)
root.event_add(V_EVENT_COPY, *SEQUENCE_COPY)
root.event_add(V_EVENT_PASTE, *SEQUENCE_PASTE)
root.event_add(V_EVENT_SELECT_ALL, *SEQUENCE_SELECT_ALL)

M_edit.add_command(
    accelerator=SHORTCUT_UNDO,
    command=lambda: manipulate(V_EVENT_UNDO),
    compound=tk.LEFT,
    image=IMAGE_UNDO,
    label='Undo',
    state=tk.NORMAL,
    underline=0,
)
M_edit.add_command(
    accelerator=SHORTCUT_REDO,
    command=lambda: manipulate(V_EVENT_REDO),
    compound=tk.LEFT,
    image=IMAGE_REDO,
    label='Redo',
    state=tk.NORMAL,
    underline=0,
)

M_edit.add_separator()

M_edit.add_command(
    accelerator=SHORTCUT_CUT,
    command=lambda: manipulate(V_EVENT_CUT),
    compound=tk.LEFT,
    image=IMAGE_CUT,
    label='Cut',
    state=tk.NORMAL,
    underline=2,
)
M_edit.add_command(
    accelerator=SHORTCUT_COPY,
    command=lambda: manipulate(V_EVENT_COPY),
    compound=tk.LEFT,
    image=IMAGE_COPY,
    label='Copy',
    state=tk.NORMAL,
    underline=0,
)
M_edit.add_command(
    accelerator=SHORTCUT_PASTE,
    command=lambda: manipulate(V_EVENT_PASTE),
    compound=tk.LEFT,
    image=IMAGE_PASTE,
    label='Paste',
    state=tk.NORMAL,
    underline=0,
)

M_edit.add_separator()

M_edit.add_command(
    accelerator=SHORTCUT_SELECT_ALL,
    command=lambda: manipulate(V_EVENT_SELECT_ALL),
    compound=tk.LEFT,
    image=IMAGE_SELECT_ALL,
    label='Select All',
    state=tk.NORMAL,
    underline=7,
)

################
# Menu: Window #
################
M_window = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='Window', menu=M_window, state=tk.NORMAL, underline=0)

IMAGE_RESET = tk.PhotoImage(data=IMAGE_DATA_RESET)

M_window.add_checkbutton(
    command=always,
    label='Always on Top',
    state=tk.NORMAL,
    underline=7,
)
M_window.add_checkbutton(
    command=transparent,
    label='Transparent',
    state=tk.NORMAL,
    underline=0,
)

M_window.add_separator()

M_window.add_command(
    command=lambda: root.wm_geometry(GEOMETRY),
    compound=tk.LEFT,
    image=IMAGE_RESET,
    label='Reset',
    state=tk.NORMAL,
    underline=0,
)

##############
# Menu: Help #
##############
M_help = tk.Menu(menu, tearoff=False)

menu.add_cascade(label='Help', menu=M_help, state=tk.NORMAL, underline=0)

IMAGE_WEB_SITE = tk.PhotoImage(data=IMAGE_DATA_WEB_SITE)
IMAGE_ABOUT = tk.PhotoImage(data=IMAGE_DATA_ABOUT)

M_help.add_command(
    command=lambda: webbrowser.open('https://github.com/serhatcelik/sten', 2),
    compound=tk.LEFT,
    image=IMAGE_WEB_SITE,
    label='Web Site',
    state=tk.NORMAL,
    underline=0,
)
M_help.add_command(
    command=lambda: showinfo(title='About', message=__doc__),
    compound=tk.LEFT,
    image=IMAGE_ABOUT,
    label='About',
    state=tk.NORMAL,
    underline=0,
)

#########
# Frame #
#########
frame = tk.Frame(
    root,
    bd=B_NONE,
    bg=BLACK,
    relief=tk.FLAT,
)

frame.grid_propagate(True)

frame.grid_rowconfigure(index=0, weight=0)
frame.grid_rowconfigure(index=1, weight=1)
frame.grid_rowconfigure(index=2, weight=2)
frame.grid_rowconfigure(index=3, weight=3)
frame.grid_columnconfigure(index=0, weight=0)
frame.grid_columnconfigure(index=1, weight=1)
frame.pack_configure(
    expand=True, fill=tk.BOTH, side=tk.TOP
)

################
# Frame: Stego #
################
F_stego = tk.Frame(
    frame,
    bd=B_THIN,
    bg=BLACK,
    relief=tk.RIDGE,
)

F_stego.pack_propagate(True)

F_stego.grid_configure(
    row=0, column=0, padx=PADX, pady=PADY, sticky=tk.NSEW
)

#################
# Encode Button #
#################
B_encode = tk.Button(
    F_stego,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=B_WIDE,
    bg=WHITE,
    command=lambda: root.event_generate(V_EVENT_ENCODE),
    compound=tk.LEFT,
    fg=BLACK,
    image=IMAGE_ENCODE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    takefocus=True,
    text='Encode',
)

B_encode.pack_configure(
    expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.LEFT
)

Hovertip(
    B_encode,
    text=f'[{SHORTCUT_ENCODE}]\n{encode.__doc__}',
)

#################
# Decode Button #
#################
B_decode = tk.Button(
    F_stego,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=B_WIDE,
    bg=WHITE,
    command=lambda: root.event_generate(V_EVENT_DECODE),
    compound=tk.LEFT,
    fg=BLACK,
    image=IMAGE_DECODE,
    relief=tk.FLAT,
    state=tk.DISABLED,
    takefocus=True,
    text='Decode',
)

B_decode.pack_configure(
    expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.LEFT
)

Hovertip(
    B_decode,
    text=f'[{SHORTCUT_DECODE}]\n{decode.__doc__}',
)

###############
# Frame: Info #
###############
F_info = tk.Frame(
    frame,
    bd=B_THIN,
    bg=BLACK,
    relief=tk.RIDGE,
)

F_info.grid_propagate(True)

F_info.grid_rowconfigure(index=0, weight=1)
F_info.grid_rowconfigure(index=1, weight=1)
F_info.grid_columnconfigure(index=0, weight=0)
F_info.grid_columnconfigure(index=1, weight=1)
F_info.grid_columnconfigure(index=2, weight=0)
F_info.grid_configure(
    row=0, column=1, padx=PADX, pady=PADY, sticky=tk.NSEW
)

#######################
# Opened File Section #
#######################
tk.Label(
    F_info,
    anchor=tk.CENTER,
    bd=B_NONE,
    bg=BLACK,
    fg=WHITE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    takefocus=False,
    text='Opened',
).grid_configure(row=0, column=0, padx=PADX, pady=PADY, sticky=tk.NSEW)

tk.Entry(
    F_info,
    bd=B_NONE,
    fg=BLACK,
    readonlybackground=BUTTON,
    relief=tk.FLAT,
    state='readonly',
    takefocus=False,
    textvariable=(Var_opened := tk.StringVar()),
).grid_configure(row=0, column=1, padx=PADX, pady=PADY, sticky=tk.NSEW)

B_open = tk.Button(
    F_info,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=B_WIDE,
    bg=WHITE,
    command=lambda: root.event_generate(V_EVENT_OPEN_FILE),
    fg=BLACK,
    relief=tk.FLAT,
    state=tk.NORMAL,
    takefocus=True,
    text='Open',
)

B_open.grid_configure(row=0, column=2, padx=PADX, pady=PADY, sticky=tk.NSEW)

Hovertip(
    B_open,
    text=f'[{SHORTCUT_OPEN_FILE}]\n{openasfile.__doc__}',
)

#######################
# Output File Section #
#######################
tk.Label(
    F_info,
    anchor=tk.CENTER,
    bd=B_NONE,
    bg=BLACK,
    fg=WHITE,
    relief=tk.FLAT,
    state=tk.NORMAL,
    takefocus=False,
    text='Output',
).grid_configure(row=1, column=0, padx=PADX, pady=PADY, sticky=tk.NSEW)

tk.Entry(
    F_info,
    bd=B_NONE,
    fg=BLACK,
    readonlybackground=BUTTON,
    relief=tk.FLAT,
    state='readonly',
    takefocus=False,
    textvariable=(Var_output := tk.StringVar()),
).grid_configure(row=1, column=1, padx=PADX, pady=PADY, sticky=tk.NSEW)

B_show = tk.Button(
    F_info,
    activebackground=WHITE,
    anchor=tk.CENTER,
    bd=B_WIDE,
    bg=WHITE,
    command=show,
    fg=BLACK,
    relief=tk.FLAT,
    state=tk.DISABLED,
    takefocus=True,
    text='Show',
)

B_show.grid_configure(row=1, column=2, padx=PADX, pady=PADY, sticky=tk.NSEW)

Hovertip(
    B_show,
    text=show.__doc__,
)

###############
# Frame: PRNG #
###############
F_prng = tk.LabelFrame(
    frame,
    bd=B_THIN,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='PRNG',
)

F_prng.pack_propagate(True)

F_prng.grid_configure(
    row=1, column=0, padx=PADX, pady=PADY, sticky=tk.NSEW
)

###################
# PRNG Seed Entry #
###################
E_prng = tk.Entry(
    F_prng,
    bd=B_NONE,
    bg=WHITE,
    disabledbackground=BUTTON,
    fg=BLACK,
    relief=tk.FLAT,
    show=ENTRY_SHOW_CHAR,
    state=tk.DISABLED,
    takefocus=True,
)

E_prng.bind(V_EVENT_PASTE, lambda e: 'break')

E_prng.pack_configure(
    expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.TOP
)

Hovertip(
    E_prng,
    text='Pseudo-random number generator seed.',
)

#################
# Frame: Crypto #
#################
F_crypto = tk.LabelFrame(
    frame,
    bd=B_THIN,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='Encryption',
)

F_crypto.pack_propagate(True)

F_crypto.grid_configure(
    row=2, column=0, padx=PADX, pady=PADY, sticky=tk.NSEW
)

####################
# Ciphers Combobox #
####################
X_ciphers = ttk.Combobox(
    F_crypto,
    background=WHITE,
    foreground=BLACK,
    state=tk.DISABLED,
    takefocus=True,
    values=tuple(crypto.ciphers),
)

X_ciphers.current(1)

X_ciphers.pack_configure(
    expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.TOP
)

Hovertip(
    X_ciphers,
    text=crypto.__doc__,
)

####################
# Cipher Key Entry #
####################
name_vcmd = {
    name: (root.register(cipher.validate), *cipher.code)
    for name, cipher in crypto.ciphers.items()
}

E_key = tk.Entry(
    F_crypto,
    bd=B_NONE,
    bg=WHITE,
    disabledbackground=BUTTON,
    fg=BLACK,
    relief=tk.FLAT,
    show=ENTRY_SHOW_CHAR,
    state=tk.DISABLED,
    takefocus=True,
    validate='key',
    vcmd=name_vcmd[X_ciphers.get()],
)

E_key.bind(V_EVENT_PASTE, lambda e: 'break')

E_key.pack_configure(
    expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.TOP
)

Hovertip(
    E_key,
    text='Cipher key.',
)

##############
# Frame: LSB #
##############
F_lsb = tk.LabelFrame(
    frame,
    bd=B_THIN,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.S,
    relief=tk.RIDGE,
    text='LSB',
)

F_lsb.pack_propagate(True)

F_lsb.grid_configure(
    row=3, column=0, padx=PADX, pady=PADY, sticky=tk.NSEW
)

##############
# LSB Scales #
##############
scales = [
    tk.Scale(F_lsb, fg=BLACK, from_=B, to=0, troughcolor=color)
    for color in (RED, GREEN, BLUE)
]

possibilities = [
    tuple(compress(enumerate(t), t)) for t in product(range(B + 1), repeat=RGB)
]

for scale in scales:
    scale.set(1)  # Do not change the position of this line!
    scale.configure(
        bd=B_THIN,
        relief=tk.FLAT,
        sliderlength=50,
        sliderrelief=tk.RAISED,
        state=tk.DISABLED,
        takefocus=True,
    )
    scale.pack_configure(
        expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.LEFT
    )

###################
# Frame: Notebook #
###################
mapping = {'used': 0, 'left': 0, 'limit': 0}

template = string.Template('$used+$left=$limit')

F_book = tk.LabelFrame(
    frame,
    bd=B_THIN,
    bg=BLACK,
    fg=WHITE,
    labelanchor=tk.SE,
    relief=tk.RIDGE,
    text=template.substitute(mapping),
)

F_book.pack_propagate(True)

F_book.grid_configure(
    row=1, column=1, rowspan=3, padx=PADX, pady=PADY, sticky=tk.NSEW
)

##################
# Stego Notebook #
##################
notebook = {}

N_stego = ttk.Notebook(
    F_book,
    takefocus=True,
)

N_stego.pack_configure(
    expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.TOP
)

for title in ['encode', 'decode']:
    tab = ScrolledText(
        N_stego,
        bd=B_NONE,
        bg=WHITE,
        fg=BLACK,
        relief=tk.FLAT,
        state=tk.NORMAL,
        tabs=1,
        takefocus=False,
        undo=True,
        wrap='char',
    )
    tab.pack_configure(
        expand=True, fill=tk.BOTH, padx=PADX, pady=PADY, side=tk.TOP
    )
    N_stego.add(
        tab,
        state=tk.DISABLED,
        sticky=tk.NSEW,
        text=title.capitalize(),
    )
    notebook.update({title: tab})

#################
# Configuration #
#################
database = Db(os.path.join(os.path.dirname(__file__), 'sten.db'))

database.create()

config = collections.defaultdict(
    lambda: tk.BooleanVar(value=False),
    {row: tk.BooleanVar(value=True) for row, in database.fetchall()}
)

if __name__ == '__main__':
    root.mainloop()
