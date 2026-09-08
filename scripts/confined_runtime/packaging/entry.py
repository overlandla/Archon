"""Source-only installed bootstrap; flags apply before any application imports."""
import sys

if (not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode
        or sys.pycache_prefix != '/dev/null'):
    raise SystemExit('unsupported_python_bootstrap')

# Before filesystem imports, check CPython's already-loaded module origins.
# The policy inventory binds these stdlib/startup locations, including bytecode.
startup_roots = tuple(f'{root}/lib/python{sys.version_info.major}.{sys.version_info.minor}/'
                      for root in {sys.base_prefix, sys.base_exec_prefix})
startup_archives = tuple(f'{root}/lib/python{sys.version_info.major}{sys.version_info.minor}.zip/'
                         for root in {sys.base_prefix, sys.base_exec_prefix})
for module in tuple(sys.modules.values()):
    origin = getattr(getattr(module, '__spec__', None), 'origin', None)
    if origin not in (None, 'built-in', 'frozen') and not origin.startswith(startup_roots + startup_archives):
        raise SystemExit('unsupported_python_startup_origin')

# Use the interpreter's frozen machinery before importing any filesystem module.
# -B alone prevents writes, not reads. Compile source directly and disallow both
# sourceless bytecode and ZIP imports, including for dependencies loaded later.
external = sys.modules['_frozen_importlib_external']

def source_code(loader, fullname):
    path = loader.get_filename(fullname)
    return loader.source_to_code(loader.get_data(path), path)

external.SourceFileLoader.get_code = source_code
sys.path_hooks[:] = [external.FileFinder.path_hook(
    (external.SourceFileLoader, external.SOURCE_SUFFIXES),
    (external.ExtensionFileLoader, external.EXTENSION_SUFFIXES),
)]
sys.path_importer_cache.clear()

from pathlib import Path

release = Path(__file__).resolve().parents[3]
# Never expose the release root as a general import root: a stray pathlib.py
# there must not replace stdlib. This namespace also never executes scripts' init.
scripts = type(sys)('scripts')
scripts.__path__ = [str(release / 'scripts')]
sys.modules['scripts'] = scripts
# -S deliberately skips .pth/sitecustomize and Python 3.13's venv prefix setup.
# Add the one installed dependency directory without running site.addsitedir.
site_packages = release / 'venv/lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'site-packages'
if site_packages.is_dir():
    sys.path.append(str(site_packages))

# rglob does not descend directory aliases. Reject them before importing trusted
# application/dependency code; layout aliases (venv/lib etc.) remain explicit.
for root in [release / 'scripts', *(Path(value) for value in sys.path)]:
    if root.is_dir():
        for path in root.rglob('*'):
            if path.is_symlink() and path.is_dir():
                raise SystemExit('unsupported_import_directory_alias')

if len(sys.argv) > 1 and sys.argv[1] == 'watchdog':
    from scripts.confined_runtime.watchdog import guard
    raise SystemExit(guard(sys.argv[2], float(sys.argv[3]), sys.argv[4]))

from scripts.confined_runtime.service import main

raise SystemExit(main())
