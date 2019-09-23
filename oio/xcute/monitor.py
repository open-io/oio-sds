import json
from oio.common.redis_conn import RedisConn
from oio.xcute import _uuid, Action

class Task(object):
    def __init__(self, nsname, batch_id, task_id, task):
        super(Task, self).__init__()
        self.batch_id = batch_id
        self.task_id = task_id
        self.task = task

    def raw(self):
        return {'bid': self.batch_id, 'tid': self.task_id, 't': self.task}

    def __repr__(self):
        return 'Task' + json.dumps(self.raw())

    def __call__(self, handle):
        try:
            self.task(handle)
        finally:
            # TODO(jfs): remove the task from the repository


class Batch(RedisConn):
    def __init__(self, conf, id_=None, conf, connection=None):
        self.conf = conf
        self.batch_id = _uuid(id_)

    def start(self, generator, cls_executor):
        assert(self.batch_id is None)
        self.batch_id = _uuid(None)
        # TODO(jfs): register the batch in the repository
        for item in generator():
            # TODO(jfs): register the task in the repository
            todo = Task(self.batch_id, _uuid(None),
                        Action(None, cls_executor(item))

    def resume(self):
        assert(self.batch_id is not None)

    def pause(self):
        assert(self.batch_id is not None)

    def join(self):
        assert(self.batch_id is not None)
