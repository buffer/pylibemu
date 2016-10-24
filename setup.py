import sys
import os
import fnmatch
import shlex
import errno
from subprocess import check_call
from subprocess import check_output
from subprocess import CalledProcessError
from distutils.core import setup
from distutils.extension import Extension
from distutils.command.build_clib import build_clib
from distutils import log
from distutils.sysconfig import get_config_var
from distutils.sysconfig import get_config_vars
from distutils.dir_util import mkpath
from distutils.file_util import copy_file

try:
    from Cython.Distutils import build_ext
    has_cython = True
except ImportError:
    has_cython = False

class build_external_clib(build_clib):
    def __init__(self, dist):
        build_clib.__init__(self, dist)
        self.build_args = {}

    def env(self):
        try:
            env = self._env
        except AttributeError:
            env = dict(os.environ)

            try:
                check_output(['pkg-config', '--version'])
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
                log.warn('pkg-config is not installed, falling back to pykg-config')
                env['PKG_CONFIG'] = sys.executable + ' ' + os.path.abspath('run_pykg_config.py')
            else:
                env['PKG_CONFIG'] = 'pkg-config'

            build_clib = os.path.realpath(self.build_clib)
            pkg_config_path = (os.path.join(build_clib, 'lib64', 'pkgconfig') +
                               ':' +
                               os.path.join(build_clib, 'lib', 'pkgconfig'))
            try:
                pkg_config_path += ':' + env['PKG_CONFIG_PATH']
            except KeyError:
                pass

            env['PKG_CONFIG_PATH'] = pkg_config_path
            self._env = env

        return env

    def pkgconfig(self, *packages):
        env        = self.env()
        PKG_CONFIG = tuple(shlex.split(env['PKG_CONFIG'], posix = (os.sep == '/')))
        kw         = {}

        index_key_flag = (
            (2, '--cflags-only-I'    , ('include_dirs',)),
            (0, '--cflags-only-other', ('extra_compile_args', 'extra_link_args')),
            (2, '--libs-only-L'      , ('library_dirs', 'runtime_library_dirs')),
            (2, '--libs-only-l'      , ('libraries',)),
            (0, '--libs-only-other'  , ('extra_link_args',)))

        for index, flag, keys in index_key_flag:
            cmd = PKG_CONFIG + (flag, ) + tuple(packages)
            log.debug('%s', ' '.join(cmd))
            args = [token[index:].decode() for token in check_output(cmd, env = env).split()]
            if args:
                for key in keys:
                    kw.setdefault(key, []).extend(args)

        return kw

    def finalize_options(self):
        build_clib.finalize_options(self)
        env = self.env()

        for lib_name, build_info in self.libraries:
            if 'sources' not in build_info:
                log.info("running 'autoreconf -v -i -f' for library '%s'", lib_name)
                check_call(['autoreconf', '-v', '-i', '-f'], cwd = build_info['local_source'], env = env)

    def build_library(self, library, pkg_config_name, local_source = None, supports_non_srcdir_builds = True, prefix = None):
        log.info("checking if library '%s' is installed", library)
        try:
            build_args = self.pkgconfig(pkg_config_name)
            log.info("found '%s' installed, using it", library)
        except CalledProcessError:
            if local_source is None:
                raise DistutilsExecError("library '%s' is not installed", library)

            log.info("building library '%s' from source", library)

            env = self.env()

            cc, cxx, opt, cflags = get_config_vars('CC', 'CXX', 'OPT', 'CFLAGS')
            cxxflags = cflags

            if 'CC' in env:
                cc = env['CC']
            if 'CXX' in env:
                cxx = env['CXX']
            if 'CFLAGS' in env:
                cflags = opt + ' ' + env['CFLAGS']
            if 'CXXFLAGS' in env:
                cxxflags = opt + ' ' + env['CXXFLAGS']

            build_temp = os.path.realpath(os.path.join(self.build_temp, library))
            build_clib = os.path.realpath(self.build_clib)
            mkpath(build_temp)
            mkpath(build_clib)

            if not supports_non_srcdir_builds:
                self._stage_files_recursive(local_source, build_temp)

            cmd = ['/bin/sh',
                   os.path.join(os.path.realpath(local_source), 'configure')]

            if prefix:
                cmd.append('--prefix=%s' % (prefix, ))

            log.info('%s', ' '.join(cmd))
            check_call(cmd,
                       cwd = build_temp,
                       env = dict(env, CC = cc, CXX = cxx, CFLAGS = cflags, CXXFLAGS = cxxflags))

            cmd = ['make', 'install']
            log.info('%s', ' '.join(cmd))
            check_call(cmd, cwd = build_temp, env = env)
            build_args = self.pkgconfig(pkg_config_name)

        return build_args

    @staticmethod
    def _list_files_recursive(path, skip=('.*', '*.o', 'autom4te.cache')):
        for dirpath, dirnames, filenames in os.walk(path, followlinks=True):
            if not any(any(fnmatch.fnmatch(p, s) for s in skip) for p in dirpath.split(os.sep)):
                for filename in filenames:
                    if not any(fnmatch.fnmatch(filename, s) for s in skip):
                        yield os.path.join(dirpath, filename)

    @staticmethod
    def _stage_files_recursive(src, dest, skip=None):
        if hasattr(os, 'link'):
            link = 'hard'
        elif hasattr(os, 'symlink'):
            link = 'sym'
        else:
            link = None

        for dirpath, dirnames, filenames in os.walk(src, followlinks=True):
            if not any(p.startswith('.') for p in dirpath.split(os.sep)):
                dest_dirpath = os.path.join(dest, dirpath.split(src, 1)[1].lstrip(os.sep))
                mkpath(dest_dirpath)
                for filename in filenames:
                    if not filename.startswith('.'):
                        src_path = os.path.join(dirpath, filename)
                        dest_path = os.path.join(dest_dirpath, filename)
                        if not os.path.exists(dest_path):
                            copy_file(os.path.join(dirpath, filename), os.path.join(dest_dirpath, filename))

    def get_source_files(self):
        self.check_library_list(self.libraries)
        filenames = []
        for (lib_name, build_info) in self.libraries:
            sources = build_info.get('sources')
            if sources is None or not isinstance(sources, (list, tuple)):
                sources = list(self._list_files_recursive(build_info['local_source']))

            filenames.extend(sources)
        return filenames

    def build_libraries(self, libraries):
        for lib_name, build_info in libraries:
            ldconf = build_info.pop('ldconf', None)
            if 'sources' not in build_info:
                for key, value in self.build_library(lib_name, **build_info).items():
                    if key in self.build_args:
                        self.build_args[key].extend(value)
                    else:
                        self.build_args[key] = value

            if ldconf and os.access(ldconf['conf'], os.W_OK):
                with open(ldconf['conf'], 'w') as f:
                    f.write(ldconf['path'])

                cmd = ['ldconfig']
                check_call(cmd)

        build_clib.build_libraries(self, ((lib_name, build_info)
            for lib_name, build_info in libraries if 'sources' in build_info))


#sourcefiles = ['src/pylibemu.pyx']
#cmdclass    = { 'build_ext' : build_ext, 'build_clib' : build_external_clib }
sourcefiles = ['src/pylibemu.c']
cmdclass    = {'build_clib' : build_external_clib}

setup(
    name             = "pylibemu",
    packages         = [],
    version          = "0.5.8",
    description      = "Libemu Python wrapper",
    url              = "https://github.com/buffer/pylibemu",
    download_url     = "https://github.com/buffer/pylibemu/archive/v0.5.6.tar.gz",
    author           = "Angelo Dell'Aera",
    author_email     = "angelo.dellaera@honeynet.org",
    maintainer       = "Angelo Dell'Aera",
    maintainer_email = "angelo.dellaera@honeynet.org",
    classifiers      = [
        "Programming Language :: Cython",
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: Unix",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        ],
    libraries = [
          ('emu', {
           'pkg_config_name'           : 'libemu',
           'local_source'              : 'submodules/libemu',
           'prefix'                    : '/opt/libemu',
           'ldconf'                    : {
                                          'conf': '/etc/ld.so.conf.d/libemu.conf',
                                          'path': '/opt/libemu/lib/',
                                         },
           'supports_non_srcdir_builds': False}),
      ],
    cmdclass        = cmdclass,
    keywords         = ['libemu', 'pylibemu', 'shellcode'],
    ext_modules      = [Extension("pylibemu",
                              sources = sourcefiles,
                              include_dirs = ["/opt/libemu/include"],
                              library_dirs = ["/opt/libemu/lib"], 
                              libraries    = ["emu"]
                              )],
)
