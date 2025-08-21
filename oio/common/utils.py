# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import grp
import hashlib
import json
import os
import pwd
import re
import sys
import time
from codecs import getdecoder, getencoder
from collections import OrderedDict
from ctypes import CDLL as orig_CDLL
from getpass import getuser
from io import RawIOBase
from itertools import chain, islice

# from math import sqrt
from random import getrandbits

# specific import to avoid using the monkey patched one
from time import monotonic as monotonic_time
from urllib.parse import parse_qs, urlparse
from urllib.parse import quote as _quote

from blake3 import blake3

from oio.common.constants import (
    MAX_STRLEN_CHUNKID,
    MIN_STRLEN_CHUNKID,
    S3StorageClasses,
)
from oio.common.easy_value import is_hexa
from oio.common.exceptions import DeadlineReached, OioException, ServiceBusy

try:
    import multiprocessing

    CPU_COUNT = multiprocessing.cpu_count() or 1
except (ImportError, NotImplementedError):
    CPU_COUNT = 1


utf8_decoder = getdecoder("utf-8")
utf8_encoder = getencoder("utf-8")

CUSTOM_HASHER = {
    "blake3": blake3,
    # 'xxhash': xxhash3_128
}


def quote(value, safe="/"):
    if isinstance(value, str):
        (value, _len) = utf8_encoder(value, "replace")
    (valid_utf8_str, _len) = utf8_decoder(value, "replace")
    return _quote(valid_utf8_str.encode("utf-8"), safe)


def encode(input, codec="utf-8"):
    """Recursively encode a list of dictionaries"""
    if isinstance(input, dict):
        return {key: encode(value, codec) for key, value in input.items()}
    elif isinstance(input, list):
        return [encode(element, codec) for element in input]
    elif isinstance(input, str):
        return input.encode(codec)
    else:
        return input


def drop_privileges(user):
    """
    Change the effective user of the current process, resets the current
    directory to /.
    """
    if os.geteuid() == 0:
        groups = [g.gr_gid for g in grp.getgrall() if user in g.gr_mem]
        os.setgroups(groups)
    current_user = getuser()
    if user != current_user:
        try:
            user_entry = pwd.getpwnam(user)
        except KeyError as exc:
            raise OioException(
                "User %s does not exist (%s). Are you running "
                "your namespace with another user name?" % (user, exc)
            )
        try:
            os.setgid(user_entry[3])
            os.setuid(user_entry[2])
        except OSError as exc:
            raise OioException(
                "Failed to switch uid to %s or gid to %s: %s"
                % (user_entry[2], user_entry[3], exc)
            )
        os.environ["HOME"] = user_entry[5]
        try:
            os.setsid()
        except OSError:
            pass
    os.chdir("/")
    os.umask(0o22)


def paths_gen(
    volume_path, excluded_dirs=None, marker=None, hash_width=None, hash_depth=None
):
    """
    Yield paths of all regular files under `volume_path`.

    :param volume_path: path of the volume to explore
    :type volume_path: str
    :param excluded_dirs: contains excluded dirs (optional)
    :type excluded_dirs: tuple
    :param marker: name of the marker file (files are sorted if not None) (optional)
    :type marker: str
    :param hash_width: how many hexdigits used to name the indirection directories
        (mandatory if marker is set)
    :type hash_width: int
    :param hash_depth: how many levels of directories used to store chunks
        (mandatory if marker is set)
    :type hash_depth: int
    """
    if marker and (not hash_width or not hash_depth):
        raise OioException("marker cannot be used without hash_width nor hash_depth")

    # Get absolute path of the volume path
    volume_abs_path = os.path.abspath(volume_path)
    dir_marker_reached = False

    # Here, topdown=True is mandatory. It allows us to exclude some directories
    # and to sort them if needed.
    for root, dirs, files in os.walk(volume_abs_path, topdown=True):
        if volume_abs_path == root:
            # Remove directory listed in excluded dir
            if excluded_dirs is not None:
                dirs[:] = [dir for dir in dirs if dir not in excluded_dirs]
        # walk() iterates recursively on folders, need to sort them each time.
        if marker:
            dirs.sort()
            if not dir_marker_reached:
                # walk() does not return the depth comparing to the first root dir.
                # This variable permits to deduce it.
                dir_without_volume = root.replace(volume_abs_path, "").replace("/", "")
                # According to the depth, this marker will allow to exclude some dirs.
                dir_marker = marker[: hash_width + len(dir_without_volume)]
                # to be able to remove in list while iterating on it
                tmp_dirs = list(dirs)
                # Exclude dirs before markers (no need to parse them)
                for dir in tmp_dirs:
                    if f"{dir_without_volume}{dir}" < dir_marker:
                        dirs.remove(dir)
                    else:
                        # Folder marker reached in the last subfolder, there is no need
                        # to check markers deeper for this pass (aka no need for
                        # further recursive folders given by <walk()>).
                        if len(dir_marker) >= hash_width * hash_depth:
                            dir_marker_reached = True

                        # Files are sorted, no need to continue for this iteration
                        # (aka until next recursive folder given by <walk()>).
                        break

        # Here, files is not an iterator. Could be a problem for huge volumes.
        # A solution would be to reimplement "os.walk".
        # Advantage: we are able to sort this list if needed.
        if files and marker:
            files.sort()
        for file in files:
            if marker and marker >= file:  # string comparison possible as chunk sorted
                # Continue until the marker
                continue
            yield os.path.join(root, file)


def statfs(volume):
    """
    :param volume: path to the mount point to get stats from.
    :returns: the free space ratio.
    :rtype: `float`
    """
    st = os.statvfs(volume)
    free_inodes = st.f_ffree
    total_inodes = st.f_files
    free_blocks = st.f_bavail
    total_blocks = st.f_blocks
    if total_inodes > 0:
        inode_ratio = free_inodes / total_inodes
    else:
        inode_ratio = 1.0
    if total_blocks > 0:
        block_ratio = free_blocks / total_blocks
    else:
        block_ratio = 1.0
    return min(inode_ratio, block_ratio)


class CacheDict(OrderedDict):
    """
    OrderedDict subclass which holds a limited number of items.
    """

    def __init__(self, size=262144):
        super(CacheDict, self).__init__()
        self.size = size

    def __setitem__(self, key, value):
        super(CacheDict, self).__setitem__(key, value)
        self._check_size()

    def _check_size(self):
        while len(self) > self.size:
            self.popitem(last=False)


class RingBuffer(list):
    def __init__(self, size=1):
        self._count = 0
        self._zero = 0
        self._size = size

    @property
    def size(self):
        """Get the size of the ring buffer"""
        return self._size

    def __index(self, key):
        if not self._count:
            raise IndexError("list index out of range")
        if isinstance(key, slice):
            start = (key.start + self._zero) % self._count
            stop = key.stop or (self._count + 1)
            return slice(start, stop)
        return (key + self._zero) % self._count

    def append(self, value):
        if self._count < self._size:
            super(RingBuffer, self).append(value)
            self._count += 1
        else:
            super(RingBuffer, self).__setitem__(self._zero % self._size, value)
            self._zero += 1

    def __getitem__(self, key):
        return super(RingBuffer, self).__getitem__(self.__index(key))

    def __setitem__(self, key, value):
        return super(RingBuffer, self).__setitem__(self.__index(key), value)

    def __delitem__(self, key):
        raise TypeError("Delete impossible in RingBuffer")

    def __iter__(self):
        for i in range(0, self._count):
            yield self[i]


def cid_from_name(account: str, ref: str) -> str:
    """
    Compute a container ID from an account and a reference name.
    """
    hash_ = hashlib.new("sha256")
    hash_.update(account.encode("utf-8"))
    hash_.update(b"\0")
    hash_.update(ref.encode("utf-8"))
    return hash_.hexdigest().upper()


def fix_ranges(ranges, length):
    if length is None or not ranges or ranges == []:
        return None
    result = []
    for r in ranges:
        start, end = r
        if start is None:
            if end == 0:
                # bytes=-0
                continue
            elif end >= length:
                # all content must be returned
                result.append((0, length - 1))
            else:
                result.append((length - end, length - 1))
            continue
        if end is None:
            if start < length:
                result.append((start, length - 1))
            else:
                # skip
                continue
        elif start < length:
            result.append((start, min(end, length - 1)))

    return result


def request_id(prefix=""):
    """
    Build a 128-bit request id string.

    :param prefix: optional prefix to the request id.
    """
    pref_bits = min(26, len(prefix)) * 4
    rand_bits = 112 - pref_bits
    return f"{prefix:.26s}{os.getpid():04X}{getrandbits(rand_bits):0{rand_bits // 4}X}"


class GeneratorIO(RawIOBase):
    """
    Make a file-like object from a generator.
    `gen` is the generator to read.
    `sub_generator` is deprecated.
    """

    def __init__(self, gen, sub_generator=False, iter_size=8192):
        self.generator = self._wrap(gen)
        self.iter_size = iter_size
        self.byte_generator = chain.from_iterable(self.generator)

    def _wrap(self, gen):
        """
        Wrap the provided generator so it yields bytes objects
        and not single bytes.
        """
        if isinstance(gen, bytes):
            yield gen
            return
        for part in gen:
            yield part

    def readable(self):
        return True

    def read(self, size=None):
        if size is not None:
            buf = bytes(islice(self.byte_generator, size))
            return buf
        try:
            return next(self.generator)
        except StopIteration:
            return bytes(0)

    def readinto(self, b):  # pylint: disable=invalid-name
        read_len = len(b)
        read_data = self.read(read_len)
        b[0 : len(read_data)] = read_data
        return len(read_data)

    def __iter__(self):
        while True:
            buf = self.read(self.iter_size)
            if not buf:
                return
            yield buf


def get_nb_chunks(data_security):
    """
    Get the number of chunk expected for a specific data_security
    defined for a specific policy

    :param data_security: data security defined for a specific storage policy
    :type data_security: str
    :return: number of chunk expected for a specific policy
    :rtype: int
    """
    if "nb_copy" in data_security:
        # Plain storage
        return int(re.findall(r"nb_copy=\d+", data_security)[0].split("=")[1])
    else:
        # Erasure code
        k = int(re.findall(r"k=\d+", data_security)[0].split("=")[1])
        m = int(re.findall(r"m=\d+", data_security)[0].split("=")[1])
        return k + m


def service_pool_to_dict(service_pool):
    """
    Convert service pool string to dict

    :param service_pool: service pool to convert
    :type service_pool: str
    """
    res_dict = {"services": []}
    pool_params = service_pool.split(";")
    for p in pool_params:
        # fair_location_constraint=9.9.2.1
        # min_dist=1
        # warn_dist=0
        if "=" in p:
            key, value = p.split("=", 1)
            res_dict[key] = value
        else:
            # Examples: "1,rawx-even,rawx", "1,account"
            count, *fallbacks = p.split(",")
            res_dict["services"].append((int(count), fallbacks))

    return res_dict


def group_chunk_errors(chunk_err_iter):
    """
    Group errors in a dictionary of lists.
    The keys are errors, the values are lists of chunk IDs.
    """
    errors = {}
    for chunk, err in chunk_err_iter:
        err_list = errors.setdefault(err, [])
        err_list.append(chunk)
    return errors


def depaginate(
    func,
    item_key=None,
    listing_key=None,
    marker_key=None,
    version_marker_key=None,
    truncated_key=None,
    attempts=1,
    *args,
    **kwargs,
):
    """
    Yield items from the lists returned by the repetitive calls
    to `func(*args, **kwargs)`. For each call (except the first),
    the marker is taken from the last element returned by the previous
    call (unless `marker_key` is provided). The listing stops after
    an empty listing is returned (unless `truncated_key` is provided).

    :param item_key: an accessor to the actual item that should be yielded,
        applied on each element of the listing
    :param listing_key: an accessor to the actual listing, applied
        on the result of `func(*args, **kwargs)`
    :param marker_key: an accessor to the next marker from the previous
        listing, applied on the result of `func(*args, **kwargs)`
    :param truncated_key: an accessor telling if the listing is truncated,
        applied on the result of `func(*args, **kwargs)`
    """
    if not item_key:
        # pylint: disable=function-redefined, missing-docstring
        def item_key(item):
            return item

    if not listing_key:
        # pylint: disable=function-redefined, missing-docstring
        def listing_key(listing):
            return listing

    if not marker_key:
        # pylint: disable=function-redefined, missing-docstring
        def marker_key(listing):
            return listing[-1]

    if not truncated_key:
        # pylint: disable=function-redefined, missing-docstring
        def truncated_key(listing):
            return bool(listing_key(listing))

    for i in range(attempts):
        try:
            raw_listing = func(*args, **kwargs)
            break
        except ServiceBusy:
            if i >= attempts - 1:
                raise
    listing = listing_key(raw_listing)
    for item in listing:
        yield item_key(item)

    while truncated_key(raw_listing):
        kwargs["marker"] = marker_key(raw_listing)
        if version_marker_key:
            kwargs["version_marker"] = version_marker_key(raw_listing)
        for i in range(attempts):
            try:
                raw_listing = func(*args, **kwargs)
                break
            except ServiceBusy:
                if i >= attempts - 1:
                    raise
        listing = listing_key(raw_listing)
        if listing:
            for item in listing:
                yield item_key(item)


def deadline_to_timeout(deadline, check=False):
    """Convert a deadline (`float` seconds) to a timeout (`float` seconds)"""
    dl_to = deadline - monotonic_time()
    if check and dl_to <= 0.0:
        raise DeadlineReached
    return dl_to


def timeout_to_deadline(timeout, now=None):
    """Convert a timeout (`float` seconds) to a deadline (`float` seconds)."""
    if now is None:
        now = monotonic_time()
    return now + timeout


def set_deadline_from_read_timeout(kwargs, force=False):
    """
    Compute a deadline from a read timeout, and set it in a keyword
    argument dictionary if there is none (or `force` is set).
    """
    to = kwargs.get("read_timeout")
    if to is not None and (force or "deadline" not in kwargs):
        kwargs["deadline"] = timeout_to_deadline(to)


def lower_dict_keys(mydict):
    """Convert all dict keys to lower case."""
    old_keys = list()
    for k, v in mydict.items():
        nk = k.lower()
        if nk == k:
            continue
        mydict[nk] = v
        old_keys.append(k)
    for k in old_keys:
        del mydict[k]


def compute_perfdata_stats(perfdata, prefix="upload."):
    """
    Compute extra statistics from a dictionary of performance data.
    """
    rawx_perfdata = perfdata.get("rawx")
    if not rawx_perfdata:
        return
    count = 0
    max_ = 0
    tot = 0
    # XXX: standard deviation computation disabled because we don't care.
    # stot = 0
    for k, v in rawx_perfdata.items():
        if k.startswith(prefix):
            tot += v
            # stot += v ** 2
            count += 1
            if v > max_:
                max_ = v
    count = count or 1
    avg = tot / count
    # sdev = sqrt(stot / count - avg ** 2)
    rawx_perfdata[prefix + "AVG"] = avg
    # rawx_perfdata[prefix + 'SD'] = sdev
    # rawx_perfdata[prefix + 'RSD'] = sdev / (avg or 1)
    rawx_perfdata[prefix + "MAX"] = max_


def get_virtualenv_dir(subdir=""):
    """
    Get the virtualenv directory if the code is run in a virtualenv.
    """
    # Get venv prefix...
    if hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    ):
        # In virtualenv, the venv prefix is sys.prefix
        return os.path.normpath(os.path.join(sys.prefix, subdir))
    return None


def CDLL(name, **kwargs):
    """
    Do the same as ctypes.CDLL, but first try in the virtualenv directory
    if the code is run in a virtualenv.
    """
    virtualenv_dir = get_virtualenv_dir(subdir="lib")
    if virtualenv_dir:
        # First try with the virtualenv directory
        try:
            return orig_CDLL(os.path.join(virtualenv_dir, name), **kwargs)
        except OSError:
            # Now, try without the virtualenv directory
            pass
    return orig_CDLL(name, **kwargs)


def parse_conn_str(conn_str):
    """
    Get the connection scheme, network host (or hosts)
    and a dictionary of extra arguments from a connection string.

    Example:
    >>> parse_conn_str('redis://10.0.1.27:666,10.0.1.25:667?opt1=val1&opt2=5')
    ('redis', '10.0.1.27:666,10.0.1.25:667', {'opt1': 'val1', 'opt2': '5'})
    """
    scheme, netloc, _, _, query, _ = urlparse(conn_str)
    kwargs = {k: ",".join(v) for k, v in parse_qs(query).items()}
    return scheme, netloc, kwargs


def compute_chunk_id(cid, path, version, position, policy, hash_algo="sha256"):
    """
    Compute the predictable chunk ID for the specified object version,
    position and policy.
    """
    base = cid + path + str(version) + str(position) + policy
    hash_ = get_hasher(hash_algo)
    hash_.update(base.encode("utf-8"))
    return hash_.hexdigest().upper()


class FakeChecksum(object):
    """Acts as a checksum object but does not compute anything"""

    def __init__(self, actual_checksum, name=None):
        self.checksum = actual_checksum
        self._name = name

    def hexdigest(self):
        """Returns the checksum passed as constructor parameter"""
        return self.checksum

    def update(self, *_args, **_kwargs):
        pass


def get_hasher(algorithm="blake3"):
    """
    Same hashlib.new, but supports other algorithms like 'blake3'.
    Passing None as the algorithm name will return a fake checksum object
    not computing anything.

    :raises ValueError: if the algorithm is not supported.
    """
    if not algorithm or algorithm.lower() == "none":
        return FakeChecksum("")
    if algorithm in CUSTOM_HASHER:
        return CUSTOM_HASHER[algorithm]()
    return hashlib.new(algorithm)


def is_chunk_id_valid(chunk_id):
    """
    Check if a chunk_id is valid:
        - should be between 24 and 64 hexa chars
        - should not end with pending or corrupt suffixes
    Return True if valid, False otherwise
    """
    if len(chunk_id) < MIN_STRLEN_CHUNKID or len(chunk_id) > MAX_STRLEN_CHUNKID:
        return False
    # This (by nature) also check the suffixes
    return is_hexa(chunk_id)


def find_mount_point(dirname):
    """
    Find the moutpoint associated to the given dir name.
    """
    dirname = os.path.abspath(dirname)
    while not os.path.ismount(dirname):
        dirname = os.path.dirname(dirname)
    return dirname


def rotate_list(mylist, shift=1, inplace=False):
    """
    Rotate a list.

    :param shift: the number of elements to shift (can be negative)
    :param inplace: if True, modifies the list in place
    :returns: the rotated list
    """
    if inplace:
        mylist[:] = mylist[shift:] + mylist[:shift]
        return mylist
    return mylist[shift:] + mylist[:shift]


def str_versionid_to_oio_versionid(version_id):
    """
    Convert string version id to an oio-style version id.

    :param version_id: the string version id
    :returns: the oio integer version id
    """
    if not version_id or version_id == "null":
        return None
    else:
        return int(float(version_id) * 1000000)


def oio_versionid_to_str_versionid(version_id):
    """
    Convert an oio-style version id to string version id.

    :param version_id: the oio integer version id
    :returns: the string version id
    """
    if version_id:
        return "%.6f" % (int(version_id) / 1000000.0)
    else:
        return "null"


def ratelimit(run_time, max_rate, increment=1, rate_buffer=5, time_time=None):
    """
    Will time.sleep() for the appropriate time so that the max_rate
    is never exceeded. If max_rate is 0, will not ratelimit.  The
    maximum recommended rate should not exceed (1000 * increment) a second
    as time.sleep() does involve some overhead. Returns run_time
    that should be used for subsequent calls.

    :param run_time: the running time in milliseconds of the next
                     allowable request. Best to start at zero.
    :param max_rate: The maximum rate per second allowed for the process.
    :param increment: How much to increment the counter. Useful if you want
                      to ratelimit 1024 bytes/sec and have differing sizes
                      of requests. Must be > 0 to engage rate-limiting
                      behavior.
    :param rate_buffer: Number of seconds the rate counter can drop and be
                        allowed to catch up (at a faster than listed rate).
                        A larger number will result in larger spikes in rate
                        but better average accuracy. Must be > 0 to engage
                        rate-limiting behavior.
    :param time_time: useful to not use default time.time()
    """
    if max_rate <= 0 or increment <= 0:
        return run_time

    # 1,000 milliseconds = 1 second
    clock_accuracy = 1000.0

    # Convert seconds to milliseconds
    now = (time_time or time.time()) * clock_accuracy

    # Calculate time per request in milliseconds
    time_per_request = clock_accuracy * (float(increment) / max_rate)

    # Convert rate_buffer to milliseconds and compare
    if now - run_time > rate_buffer * clock_accuracy:
        run_time = now
    elif run_time - now > 0:
        # Convert diff back to a floating point number of seconds and sleep
        time.sleep((run_time - now) / clock_accuracy)

    # Return the absolute time for the next interval in milliseconds; note
    # that time could have passed well beyond that point, but the next call
    # will catch that and skip the sleep.
    return run_time + time_per_request


def get_bucket_owner_from_acl(acl_config):
    """
    Get bucket owner from ACL configuration
    """
    if acl_config:
        acl_config = json.loads(acl_config)
    else:
        acl_config = {}
    return acl_config.get("Owner", "unknown")


def initialize_coverage(logger, context):
    import coverage

    cov = coverage.process_startup()
    if cov:
        cov.switch_context(context)
    else:
        logger.warning(
            "code coverage not started, missing environment? COVERAGE_PROCESS_START=%s",
            os.getenv("COVERAGE_PROCESS_START"),
        )


def read_storage_mappings(conf):
    """Read storage mapping from configuration

    Args:
        conf (dict): configuration to read

    Raises:
        ValueError: Raised if configuration is not valid (policy duplicates,
        invalid storage class, invalid policy)

    Returns:
        tuple: First value is the mapping from a policy to storage class.
        The second is the mapping from a storage class to its associated policies
        and theirs thresholds (object size)
    """
    storage_re = re.compile("[A-Z0-9_]+")
    policy_to_class = {}
    class_to_policy = {}
    for key, value in conf.items():
        if not key.startswith("storage_class."):
            continue
        storage_class = key[14:].upper()
        if not storage_re.match(storage_class):
            raise ValueError(f"Invalid storage class '{storage_class}'")
        try:
            S3StorageClasses(storage_class)
        except ValueError:
            raise ValueError(f"Storage class '{storage_class}' is not supported")

        policies = []
        for policy in value.split(","):
            policy = policy.strip()
            policy_name, *policy_threshold = policy.split(":", 1)
            policy_name = policy_name.strip()
            policy_threshold = (
                int(policy_threshold[0].strip()) if policy_threshold else -1
            )
            if not policy_name or not storage_re.match(policy_name):
                raise ValueError(
                    f"Invalid storage policy '{policy_name}' for storage class "
                    f"'{storage_class}'"
                )
            mapped_storage_class = policy_to_class.get(policy_name)
            if mapped_storage_class and storage_class != mapped_storage_class:
                raise ValueError(
                    f"Policy '{policy_name}' already associated to "
                    f"storage class {policy_to_class[policy_name]}"
                )
            policy_to_class[policy_name] = storage_class
            policies.append((policy_name, policy_threshold))
        policies.sort(key=lambda x: x[1], reverse=True)
        class_to_policy[storage_class] = policies

    return policy_to_class, class_to_policy
