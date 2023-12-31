This is a collection of development tools for Microchip (TM) PIC (TM)
microcontrollers.

Gputils implements a subset of features available with Microchip's tools.
See the documentation for an up-to-date list of what gputils can do.

Installation instructions are constained in the INSTALL document.

Documentation is in the `doc` directory.  The user manual is
`gputils.lyx`, it's ready for a postscript printer as `gputils.ps` or
viewing using Adobe (TM) Acrobat (TM) as `gputils.pdf`.  Lyx is
available from http://www.lyx.org

Send any bug reports to the bug tracking system at:

https://sourceforge.net/projects/gputils/

Please verify a bug report has not already been submitted before creating a
new one.  In the report, please state which version of gputils you're using,
the machine and OS you've built it for (or not), and enough source code to
reproduce the problem.

If you're trying to build gputils on a machine/OS but can't, you might
want to take a look at `stdhdr.h` and see if you can fix the problem
there.

Please send any patches you wish to be considered for the next gputils release,
to one of the Project Administrators listed at sourceforge.

## Win32 Support

Although gputils was primarily intended for GNU systems, it can be compiled
on a win32 system (Win98, WinNT, ...).  The gputils supported win32 compiler
is MinGW.  It is available at:

http://www.mingw.org/

MinGW was selected because it is based on the GNU C compiler.  Additionally,
it can easily be used as a cross compiler on GNU systems.  A native win32
version of MinGW is available.

Offical gputils ports to win32 are be generated using a cross compiler on
a Linux system by the `scripts/build/mingw/do_setup.sh` script.
