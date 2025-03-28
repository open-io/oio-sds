# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from oio.common import exceptions as exc
from oio.conscience.stats.base import BaseStat
from oio.event.beanstalk import Beanstalk, ConnectionError


class BeanstalkdStat(BaseStat):
    """Collect statistics about beanstalkd services."""

    stat_keys = {
        "current-tubes": "stat.tubes",
        "current-jobs-buried": "stat.jobs_buried",
        "current-jobs-delayed": "stat.jobs_delayed",
        "current-jobs-ready": "stat.jobs_ready",
        "current-jobs-reserved": "stat.jobs_reserved",
        "current-jobs-urgent": "stat.jobs_urgent",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._beanstalkd = None
        self._host = None
        self._port = None

    def configure(self):
        super().configure()
        for k in ("host", "port"):
            if k not in self.stat_conf:
                raise exc.ConfigurationException(
                    f'Missing field "{k}" in configuration'
                )

    @property
    def beanstalkd(self):
        if self._beanstalkd is None:
            self._host = self.stat_conf["host"]
            self._port = int(self.stat_conf["port"])
            self._beanstalkd = Beanstalk(self._host, self._port)
        return self._beanstalkd

    def get_stats(self, reqid=None):
        stats = {}
        try:
            all_stats = self.beanstalkd.stats()
            for bkey, skey in self.stat_keys.items():
                stats[skey] = all_stats[bkey]
        except ConnectionError as err:
            self.logger.warn(
                "ERROR connection lost to beanstalkd (%s:%d) %s",
                self._host,
                self._port,
                err,
            )
            self._beanstalkd = None
        except Exception as err:
            self.logger.warn(
                "ERROR performing beanstalkd check (%s:%s): %s",
                self._host,
                self._port,
                err,
            )
        finally:
            return stats
