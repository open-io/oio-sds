import pbr.version
_version_info = pbr.version.VersionInfo('oio')
__version__ = _version_info.release_string()
__canonical_version = _version_info.version_string()
