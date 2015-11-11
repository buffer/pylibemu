from distutils.core import setup
from distutils.extension import Extension
#from Cython.Distutils import build_ext

sourcefiles  = ['src/pylibemu.c']

setup(
    name             = "pylibemu",
    packages         = [],
    version          = "0.3.1",
    description      = "Libemu Python wrapper",
    url              = "https://github.com/buffer/pylibemu",
    download_url     = "https://github.com/buffer/pylibemu/archive/v0.3.1.tar.gz"
    author           = "Angelo Dell'Aera",
    author_email     = "angelo.dellaera@honeynet.org",
    maintainer       = "Angelo Dell'Aera",
    maintainer_email = "angelo.dellaera@honeynet.org",
    classifiers      = [
        "Programming Language :: Cython",
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: Unix",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        ],
    #cmdclass        = { 'build_ext' : build_ext },
    keywords         = ['libemu', 'pylibemu', 'shellcode'],
    ext_modules      = [Extension("pylibemu",
                              sourcefiles,
                              include_dirs = ["/opt/libemu/include"],
                              library_dirs = ["/opt/libemu/lib"], 
                              libraries    = ["emu"]
                              )]
)
