import collections
import ctypes
import enum
import os
import pathlib
import struct
from ctypes.util import find_library


_libc = ctypes.cdll.LoadLibrary(find_library('c'))


# These events reflect changes to files inside a directory being watched
DIRECTORY_EVENT = enum.Enum(
    'DIRECTORY_EVENT',
    [
        'MOVED',
        'CREATED',
        'DELETED'
    ]
)

# These events reflect changes to a watched file itself
FILE_EVENT = enum.Enum(
    'FILE_EVENT',
    [
        'ACCESSED',
        'MODIFIED',
        'METADATA_CHANGED',
        'CLOSED',
        'OPENED',
        'DELETED',
        'MOVED'
    ]
)


Event = collections.namedtuple('Event', ['type', 'path'])

# these come from the macro definitions in sys/inotify.h
_event_type_to_flag = {
    FILE_EVENT.ACCESSED: 0x00000001,
    FILE_EVENT.MODIFIED: 0x00000002,
    FILE_EVENT.METADATA_CHANGED: 0x00000004,
    FILE_EVENT.CLOSED: 0x00000008 | 0x00000010,
    FILE_EVENT.OPENED: 0x00000020,
    FILE_EVENT.DELETED: 0x00000400,
    FILE_EVENT.MOVED: 0x00000800,
    DIRECTORY_EVENT.MOVED: 0x00000040 | 0x00000080,
    DIRECTORY_EVENT.CREATED: 0x00000100,
    DIRECTORY_EVENT.DELETED: 0x00000200
}

def get_event_type(mask):
    for event_type, flag in _event_type_to_flag.items():
        if mask & flag:
            return event_type
    raise ValueError('Unknown event type: {:#X}'.format(mask))


def get_event_data(inotify_descriptor):
    format = 'i I I I' # wd mask cookie len
    record_length = struct.calcsize(format)

    records = []
    data = os.read(inotify_descriptor, 4096)
    while data:
        record_start = data[:record_length]
        data = data[record_length:]
        wd, mask, cookie, name_length = struct.unpack(format, record_start)
        result = {
            'wd': wd,
            'mask': mask,
            'cookie': cookie,
            'len': name_length
        }
        if name_length:
            name = data[:name_length]
            data = data[name_length:]
            result['name'] = name.rstrip(b'\x00').decode('utf-8')

        records.append(result)
    return records


def make_event(record, watchfd_map):
    p = watchfd_map[record['wd']]
    if 'name' in record:
        p = os.path.join(p, record['name'])

    type = get_event_type(record['mask'])
    return Event(type, p)


def init_descriptor():
    result = _libc.inotify_init()
    if result == -1:
        errno = ctypes.get_errno()
        raise Exception(os.strerror(errno))
    return result

def add_watch(inotify_fd, fname, flags):
    token = _libc.inotify_add_watch(inotify_fd, fname.encode('utf-8'), ctypes.c_uint(flags))
    if token == -1:
        errno = ctypes.get_errno()
        # TODO: more specific python exceptions
        raise Exception(os.strerror(errno))
    return token

def remove_watch(inotify_fd, watch_descriptor):
    result = _libc.inotify_rm_watch(inotify_fd, watch_descriptor)
    if result == -1:
        errno = ctypes.get_errno()
        raise Exception(os.strerror(errno))

class Watcher:
    def __init__(self):
        self.inotify_descriptor = init_descriptor()
        self.is_closed = False
        self.event_buf = []
        self.watchds = {}

    def __iter__(self):
        return self

    def __next__(self):
        # NOTE this will block for an event if one isn't available
        if self.is_closed:
            raise StopIteration

        if len(self.event_buf) == 0:
            records = get_event_data(self.inotify_descriptor)
            self.event_buf.extend([make_event(r, self.watchds) for r in records])
        event = self.event_buf.pop(0)
        return event

    def watch(self, path, event_types, replace=True, one_shot=False):
        if isinstance(path, pathlib.Path):
            path = str(path)

        if len(event_types) == 0:
            raise ValueError('Must supply at least one type of event')

        flag = 0
        for evt_type in event_types:
            flag |= _event_type_to_flag[evt_type]

        if not replace:
            flag |= 0x20000000

        if one_shot:
            flag |= 0x80000000

        watchd = add_watch(self.inotify_descriptor, path, flag)
        self.watchds[watchd] = path
        return watchd

    def unwatch(self, token):
        remove_watch(self.inotify_descriptor, token)

    def close(self):
        if self.is_closed:
            raise ValueError('Already closed')

        os.close(self.inotify_descriptor)
        self.is_closed = True
