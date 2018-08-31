import gdb
from gdb.FrameDecorator import FrameDecorator
import subprocess

'''
Usage in gdb:

(gdb) source SharedFrameFilter.py
(gdb) bt
#0  0x00007ffff7eb1790 in write () at 0x000ec790 in /usr/lib/libc.so.6
#1  0x00007ffff7e4185d in _IO_new_file_write () at 0x0007c85d in /usr/lib/libc.so.6
#2  0x00007ffff7e40bbf in new_do_write () at 0x0007bbbf in /usr/lib/libc.so.6
#3  0x00007ffff7e429d9 in __GI__IO_do_write () at 0x0007d9d9 in /usr/lib/libc.so.6
#4  0x00007ffff7e42db3 in __GI__IO_file_overflow ()
    at 0x0007ddb3 in /usr/lib/libc.so.6
#5  0x00007ffff7e37be2 in puts () at 0x00072be2 in /usr/lib/libc.so.6
#6  0x0000555555555050 in main ()
'''


class SharedFrameFilter():

    textOffsets = None

    def __init__(self):
        self.name = "shared_filter"
        self.priority = 100
        self.enabled = True
        self.textOffsets = {}

        # Register this frame filter with the global frame_filters
        # dictionary.
        gdb.frame_filters[self.name] = self

    def getTextOffset(self, libName):
        if libName in self.textOffsets:
            return self.textOffsets[libName]

        out = subprocess.Popen([
            "objdump",
            "--section-headers",
            "--section=.text",
            libName
        ], stdout=subprocess.PIPE).stdout.read()

        lines = out.decode("utf-8").split("\n")
        for line in lines:
            if not ".text" in line:
                continue
            cols = line.split()
            startAddr = int(cols[3], 16)

            self.textOffsets[libName] = startAddr
            return startAddr

    def filter(self, frame_iter):
        for frame in frame_iter:
            address = frame.address()
            libName = gdb.solib_name(address)
            if libName == None:
                yield frame
                continue

            absoluteAddress = 0
            shared = gdb.execute("info shared", False, True)
            for line in shared.split('\n'):
                cols = line.split()
                try:
                    int(cols[0], 16)
                except:
                    continue

                # Sooo ugly but the output is fixed lenght.
                # This way we can support paths with spaces as well.
                name = line[36:]

                if name != libName:
                    continue

                libStart = int(cols[0], 16)
                absoluteAddress = address - libStart + \
                    self.getTextOffset(libName)

                break

            frame.filename_orig = frame.filename
            frame.filename = lambda: "0x%08x in %s" % (
                absoluteAddress, frame.filename_orig())
            yield frame


SharedFrameFilter()
