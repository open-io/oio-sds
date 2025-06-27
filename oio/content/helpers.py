# Copyright (C) 2026 OVH SAS
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
import time

from oio.common.exceptions import OioNetworkException
from oio.common.green import eventlet


class RawxScoreMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__last_refresh_rawx_scores = 0.0
        self.__refresh_rawx_scores_delay = 2.0
        self.__rawx_scores = {}

    def set_refresh_rawx_scores_delay(self, delay):
        self.__refresh_rawx_scores_delay = delay

    def __get_rawx_scores(self, conscience_client):
        rawx_services = conscience_client.all_services("rawx")
        rawx_scores = dict()
        for rawx_service in rawx_services:
            # The score is only used to locate chunks (read)
            score = rawx_service.get("scores", {}).get(
                "score.get", rawx_service["score"]
            )
            if not rawx_service.get("tags", {}).get("tag.up"):
                # The oioproxy service assigns a score of -1 on the chunk location
                # where the rawx service is down
                score = -1
            rawx_scores[rawx_service["id"]] = score
        return rawx_scores

    def __refresh_rawx_scores_routine(self, consience_client, is_async=False):
        try:
            self.__rawx_scores = self.__get_rawx_scores(consience_client)
        except OioNetworkException as exc:
            self.logger.warning("Failed to refresh rawx service scores: %s", exc)
            if is_async:
                # The refresh time has already updated,
                # force refresh scores next time
                self.__last_refresh_rawx_scores = 0.0
        except Exception:
            self.logger.exception("Failed to refresh rawx service scores")
            if is_async:
                # The refresh time has already updated,
                # force refresh scores next time
                self.__last_refresh_rawx_scores = 0.0

    def __refresh_rawx_scores(self, conscience_client, now=None, **_kwargs):
        """Refresh rawx service scores."""
        if not self.__rawx_scores and self.__last_refresh_rawx_scores == 0.0:
            # It's the first request, wait the response
            self.__refresh_rawx_scores_routine(conscience_client)
        else:
            # Refresh asynchronously so as not to slow down the current request
            eventlet.spawn_n(
                self.__refresh_rawx_scores_routine, conscience_client, is_async=True
            )
        # Always update the refresh time to avoid multiple requests
        # while waiting for the response
        if not now:
            now = time.time()
        self.__last_refresh_rawx_scores = now

    def maybe_refresh_rawx_scores(self, conscience_client, **kwargs):
        """Refresh rawx service scores if delay has been reached."""
        if self.__refresh_rawx_scores_delay >= 0.0 or not self.rawx_scores:
            now = time.time()
            if now - self.__last_refresh_rawx_scores > self.__refresh_rawx_scores_delay:
                self.__refresh_rawx_scores(conscience_client, now=now, **kwargs)
        return self.__rawx_scores
