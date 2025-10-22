# Copyright (C) 2025 OVH SAS
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

from oio.common.easy_value import boolean_value
from oio.common.exceptions import ConfigurationException, NotFound
from oio.common.utils import depaginate, ratelimit
from oio.crawler.bucket.object_wrapper import ObjectWrapper, is_error, is_success
from oio.crawler.common.crawler import Crawler, PipelineWorker


class BucketWorker(PipelineWorker):
    """
    Bucket Worker responsible for a bucket.
    """

    SERVICE_TYPE = "bucket"

    def __init__(self, conf, volume_path, logger=None, api=None, **kwargs):
        """
        Here, volume_path is the name of the bucket to crawl.
        """
        self.check_volume = False
        if boolean_value(conf.get("use_marker"), False):
            raise ConfigurationException(
                "Marker feature not available for bucket crawler"
            )
        super(BucketWorker, self).__init__(
            conf, volume_path, logger=logger, api=api, **kwargs
        )

    def cb(self, status, msg):
        if is_success(status):
            pass
        elif is_error(status):
            self.logger.warning("Bucket %s handling failure: %s", self.volume_id, msg)
        else:
            self.logger.warning(
                "Bucket %s status=%d msg=%s", self.volume_id, status, msg
            )

    def crawl_volume(self):
        """
        Crawl bucket, and apply filters on every object found.
        """
        self.passes += 1

        self.report("starting", force=True)
        api = self.app_env["api"]
        account = None
        try:
            resp_show = api.bucket.bucket_show(self.volume_path)
            account = resp_show["account"]
        except NotFound:
            self.logger.error(
                "Bucket %s not found, not possible to crawl it", self.volume_path
            )
            self.errors += 1

        if account:
            last_scan_time = 0
            resp_list = depaginate(
                api.object_list,
                account=account,
                container=self.volume_path,
                listing_key=lambda x: x["objects"],
                marker_key=lambda x: x["next_marker"],
                truncated_key=lambda x: x["truncated"],
            )
            for obj in resp_list["objects"]:
                if not self.running:
                    self.logger.info("stop crawling %s", self.volume_path)
                    break

                if not self.process_entry(obj):
                    continue

                last_scan_time = ratelimit(
                    run_time=last_scan_time,
                    max_rate=self.max_scanned_per_second,
                    increment=1,
                )
                self.report("running")

        self.report("ended", force=True)
        # reset stats for each filter
        self.pipeline.reset_stats()
        # reset crawler stats
        self.errors = 0
        self.successes = 0
        self.ignored_paths = 0
        self.invalid_paths = 0

    def process_entry(self, obj, reqid=None):
        obj = ObjectWrapper(obj)
        try:
            self.pipeline(obj.env, self.cb)
            self.successes += 1
        except Exception as c_exc:
            self.errors += 1
            self.logger.exception(
                "Failed to apply pipeline on obj='%s': %s", obj.name, c_exc
            )
        self.scanned_since_last_report += 1

        return True


class BucketCrawler(Crawler):
    CRAWLER_TYPE = "bucket"
    SERVICE_TYPE = "bucket"

    def __init__(self, conf, conf_file=None, worker_class=BucketWorker, **kwargs):
        super(BucketCrawler, self).__init__(
            conf, conf_file=conf_file, worker_class=worker_class, **kwargs
        )
