from __future__ import absolute_import
import sys
import os

# Solve import crap
ROOT = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(ROOT):
    ROOT = os.readlink(ROOT)
sys.path.insert(0, os.path.dirname(ROOT) + "/")

from SharedFrameFilter import SharedFrameFilter

import gdb


class ConditionalLibBreakpoint(gdb.Breakpoint):
    """
    Creates a breakpoint that will only break if the backtrace addresses
    are not located in any of the supplied libraries

    Args:
        - [0]: symbol to break on
        - [1...]: list of addresses to ignore in 0xfefefefe format
    """

    def __init__(self, symbol, libnames):
        self.symbol = symbol
        self.libnames = libnames
        super(ConditionalLibBreakpoint, self).__init__(self.symbol)

    def stop(self):
        frame = gdb.selected_frame()
        while frame != None:
            frame = frame.older()
            prevAddr = frame.pc()
            prevLibname = gdb.solib_name(prevAddr)
            if prevLibname in self.libnames:
                return False
        return True


class ConditionalPCBreakpoint(gdb.Breakpoint):
    """
    Creates a breakpoint that will only break if the addresses in the
    backtrace doesn't contain addresses in the supplied list.

    Args:
        - [0]: symbol to break on
        - [1...]: list of addresses to ignore in 0xfefefefe format
    """

    def __init__(self, symbol, pc_list):
        self.symbol = symbol
        self.pc_list = []
        for x in pc_list:
            try:
                addr = int(x, 16)
                self.pc_list.append(addr)
            except:
                pass
        super(ConditionalPCBreakpoint, self).__init__(self.symbol)

    def stop(self):
        frame = gdb.selected_frame()
        while frame != None:
            addr = frame.pc()
            if addr in self.pc_list:
                return False
            frame = frame.older()
        return True


class CustomGDBCommand(gdb.Command):
    def __init__(self, cmdname="foo"):
        self.cmdname = cmdname
        super(CustomGDBCommand, self).__init__(self.cmdname, gdb.COMMAND_DATA)

    def invoke(self, arg_string, from_tty):
        args = arg_string.split()
        if args[0] == "whichlib":
            try:
                addr = int(args[1], 16)
                print(gdb.solib_name(addr))
            except:
                pass
        elif args[0] == "breakignorelib":
            ConditionalLibBreakpoint(args[1], args[2:])
        elif args[0] == "breakignorepc":
            ConditionalPCBreakpoint(args[1], args[2:])


class Alias(gdb.Command):
    def __init__(self, alias, command, shorttext=1):
        self._command = command
        self._alias = alias
        super(Alias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("%s %s" % (self._command, args))


Alias("whichlib", "foo whichlib")
Alias("breakignorelib", "foo breakignorelib")
Alias("breakignorepc", "foo breakignorepc")


CustomGDBCommand()
SharedFrameFilter()
