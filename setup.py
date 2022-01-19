from setuptools import setup
from setuptools.extension import Extension
from setuptools.command.build_clib import build_clib

try:
    from Cython.Distutils import build_ext
    has_cython = True
except ImportError:
    has_cython = False


# sourcefiles = ['src/pylibemu.pyx']
# cmdclass    = { 'build_ext' : build_ext, 'build_clib' : build_clib }
sourcefiles = ['src/pylibemu.c']
cmdclass    = {'build_clib' : build_clib}


setup(
    name             = "pylibemu",
    packages         = [],
    version          = "0.7",
    description      = "Libemu Python wrapper",
    url              = "https://github.com/buffer/pylibemu",
    author           = "Angelo Dell'Aera",
    author_email     = "angelo.dellaera@honeynet.org",
    maintainer       = "Angelo Dell'Aera",
    maintainer_email = "angelo.dellaera@honeynet.org",
    classifiers      = [
        "Programming Language :: Cython",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: Unix",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        ],
    cmdclass        = cmdclass,
    keywords         = ['libemu', 'pylibemu', 'shellcode'],
    ext_modules      = [Extension("pylibemu",
                              sources   = sourcefiles,
                              libraries = ["emu"]
                              )],
)
