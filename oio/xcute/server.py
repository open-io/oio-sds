from werkzeug.exceptions import BadRequest as HTTPBadRequest
from werkzeug.exceptions import NotFound as HTTPNotFound
from werkzeug.routing import Map, Rule, Submount
from werkzeug.wrappers import Response

from oio.common.easy_value import int_value, true_value
from oio.common.exceptions import NotFound
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.wsgi import WerkzeugApp
from oio.xcute.common.exceptions import UnknownJobTypeException
from oio.xcute.jobs import JOB_TYPES
from oio.xcute.common.manager import XcuteManager


class Xcute(WerkzeugApp):
    def __init__(self, conf, manager, logger=None):
        self.conf = conf
        self.manager = manager
        self.logger = logger

        url_map = Map([
            Rule('/status', endpoint='status'),
            Submount('/v1.0/xcute', [
                Rule('/jobs', endpoint='job_list',
                     methods=['POST', 'GET']),
                Rule('/jobs/<job_id>', endpoint='job',
                     methods=['GET', 'DELETE']),
                Rule('/jobs/<job_id>/pause', endpoint='job_pause',
                     methods=['POST']),
                Rule('/jobs/<job_id>/resume', endpoint='job_resume',
                     methods=['POST']),
            ])
        ])

        super(Xcute, self).__init__(url_map, logger)

    def on_status(self, req):
        status = self.manager.backend.status()
        return Response(json.dumps(status), mimetype='application/json')

    def on_job_list(self, req):
        if req.method == 'GET':
            limit = int_value(req.args.get('limit'), None)
            marker = req.args.get('marker')
            jobs = self.manager.list_jobs(limit=limit, marker=marker)

            return Response(json.dumps(jobs), mimetype='application/json')

        if req.method == 'POST':
            data = json.loads(req.data)

            job_type = data.get('type')
            if not job_type:
                raise HTTPBadRequest('Missing job type')

            job_class = JOB_TYPES.get(job_type)
            if job_class is None:
                return HTTPBadRequest(UnknownJobTypeException.message)

            job = job_class(self.conf, logger=self.logger)
            job_config = data.get('config')
            # TODO: use lock
            job_config, lock = job.load_config(job_config)

            job_id = self.manager.create(job_type, job_config)
            return Response(json.dumps({'id': job_id}), status=202)

    def on_job(self, req, job_id):
        if req.method == 'GET':
            try:
                job = self.manager.show_job(job_id)
            except NotFound as e:
                return HTTPNotFound(e.message)

            return Response(json.dumps(job), mimetype='application/json')

        if req.method == 'DELETE':
            self.manager.delete(job_id)

            return Response(status=204)

    def on_job_pause(self, req, job_id):
        self.manager.request_pause(job_id)
        return Response(status=204)

    def on_job_resume(self, req, job_id):
        self.manager.resume(job_id)
        return Response(status=204)


def create_app(conf):
    logger = get_logger(conf)
    manager = XcuteManager(conf, logger)
    app = Xcute(conf, manager, logger)

    return app
