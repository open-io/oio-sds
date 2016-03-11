import pkg_resources

try:
    __version__ = __canonical_version__ = pkg_resources.get_provider(
        pkg_resources.Requirement.parse('oio')).version
except pkg_resources.DistributionNotFound:
    import pbr.version
    _version_info = pbr.version.VersionInfo('oio')
    __version__ = _version_info.release_string()
    __canonical_version = _version_info.version_string()
