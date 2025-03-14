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

from html import escape

from gunicorn.app.base import BaseApplication
from gunicorn.glogging import Logger
from werkzeug.exceptions import (
    BadRequest,
    HTTPException,
    InternalServerError,
    ServiceUnavailable,
)
from werkzeug.wrappers import Request, Response

from oio.common.configuration import read_conf
from oio.common.constants import REQID_HEADER
from oio.common.exceptions import ServiceBusy
from oio.common.logger import get_logger
from oio.common.utils import CPU_COUNT


class Application(BaseApplication):
    access_log_fmt = (
        "%(bind0)s %(h)s:%({remote_port}e)s %(m)s %(s)s %(D)s "
        + "%(B)s %(l)s %(reqid)s %(U)s?%(q)s"
    )
    access_log_fmt_ltsv = (
        "log_type:access	local:%(bind0)s	"
        + "client_ip:%(client)s	remote_addr:%(h)s:%({remote_port}e)s	"
        + "protocol:%(H)s	method:%(m)s	path:%(U)s?%(q)s	"
        + "status_int:%(s)s	bytes_sent_int:%(b)s	"
        + "request_id:%(reqid)s	"
        + "request_time_us_int:%(D)s	user_agent:%(a)s"
    )

    def __init__(self, app, conf, post_fork=None, logger_class=None):
        self.conf = conf
        self.application = app
        self.post_fork = post_fork
        self.logger_class = logger_class
        super(Application, self).__init__()

    def load_config(self):
        for key, value in self.conf.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key, value)

        bind = "%s:%s" % (
            self.conf.get("bind_addr", "127.0.0.1"),
            self.conf.get("bind_port", "8000"),
        )
        self.cfg.set("bind", bind)
        self.cfg.set("backlog", self.conf.get("backlog", 2048))
        self.cfg.set("workers", self.conf.get("workers", CPU_COUNT))
        self.cfg.set("worker_class", self.conf.get("worker_class", "eventlet"))
        self.cfg.set("worker_connections", self.conf.get("worker_connections", 1000))
        self.cfg.set("syslog_prefix", self.conf.get("syslog_prefix", ""))
        log_addr = self.conf.get("log_address", "/dev/log")
        if "://" not in log_addr:
            log_addr = "unix://" + log_addr
        self.cfg.set("syslog_addr", log_addr)
        self.cfg.set("syslog", True)
        self.cfg.set("keepalive", 30)
        self.cfg.set(
            "access_log_format",
            self.conf.get("access_log_format", self.access_log_fmt_ltsv),
        )
        self.cfg.set(
            "proc_name", self.conf.get("proc_name", self.application.__class__.__name__)
        )
        self.cfg.set("logger_class", self.logger_class)
        if self.post_fork:
            self.cfg.set("post_fork", self.post_fork)

    def load(self):
        return self.application


class ServiceLogger(Logger):
    def setup(self, cfg):
        # The process ID is already logged by syslog, we don't want it twice.
        if r"%(process)d" in self.syslog_fmt:
            # self.syslog_fmt may actually be a class variable, but we can
            # mask it with an instance variable.
            self.syslog_fmt = "%(message)s"
        super(ServiceLogger, self).setup(cfg)

    def atoms(self, resp, req, environ, request_time):
        atoms = super(ServiceLogger, self).atoms(resp, req, environ, request_time)
        # We may bind on several addresses and ports but I don't
        # know how to identify for which one we are logging
        index = 0
        for bind in self.cfg.bind:
            atoms["bind%d" % index] = bind
            index += 1

        # Since the account service serves IAM requests, we may get requests
        # not coming from oio-sds services, hence with a different request ID
        # header.
        atoms["reqid"] = atoms.get(
            f"{{{REQID_HEADER}}}i",
            atoms.get(
                "{x-openstack-request-id}i", atoms.get("{http_x_oio_req_id}e", "-")
            ),
        )
        atoms["client"] = atoms.get("{x-forwarded-for}i", atoms["h"])
        return atoms

    def access(self, resp, req, environ, request_time):
        # do not log status requests
        if environ.get("PATH_INFO", "/") != "/status":
            super(ServiceLogger, self).access(resp, req, environ, request_time)


class WerkzeugApp(object):
    def __init__(self, url_map=None, logger=None):
        self.url_map = url_map
        self.logger = logger or get_logger(None)

    def dispatch_request(self, req):
        adapter = self.url_map.bind_to_environ(req.environ)
        reqid = self.find_request_id(req)
        try:
            endpoint, params = adapter.match()
            params["reqid"] = reqid
            resp = getattr(self, "on_" + endpoint)(req, **params)
        except HTTPException as exc:
            resp = exc
        except ServiceBusy as exc:
            if self.logger:
                self.logger.error("%s (reqid=%s)", exc, reqid)
            resp = ServiceUnavailable(f"Could not satisfy the request: {exc}")
        except ValueError as exc:
            resp = BadRequest(description=str(exc))
        except Exception as exc:
            if self.logger:
                self.logger.exception(
                    "ERROR Unhandled exception in request (reqid=%s)",
                    reqid,
                )
            resp = InternalServerError(f"Unmanaged error: {exc}")
        if isinstance(resp, HTTPException) and not resp.response:
            resp.response = Response(
                escape(resp.description, quote=True),
                status=resp.code,
                headers=[(REQID_HEADER, reqid)],
            )
        return resp

    def find_request_id(self, req):
        """
        Find a request ID in the request environment.
        """
        for key in ("HTTP_X_OIO_REQ_ID", "HTTP_X_OPENSTACK_REQUEST_ID"):
            val = req.environ.get(key)
            if val:
                return val
        return None

    def wsgi_app(self, environ, start_response):
        req = Request(environ)
        resp = self.dispatch_request(req)
        return resp(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def init_request_processor(conf_file, app_name, app_factory, *args, **kwargs):
    conf = read_conf(conf_file, app_name)
    if "logger" in kwargs:
        logger = kwargs.pop("logger")
    else:
        logger = get_logger(conf, app_name, verbose=kwargs.pop("verbose", False))
    app = app_factory(conf)
    return (app, conf, logger, app_name)
