import redis
import time
import uuid
import math

CODE_SYSTEM_ERROR = 501
CODE_ACCOUNT_NOTFOUND = 431
CODE_USER_NOTFOUND = 432

account_fields = ['ns', 'name', 'ctime', 'container_count', 'object_count',
                  'bytes', 'storage_policy', 'properties']

container_fields = [
    'ns', 'account', 'reference', 'type', 'object_count', 'bytes',
    'ctime', 'mtime']


class AccountException(Exception):
    def __init__(self, c=500, m="AccountException"):
        Exception.__init__(self)
        self.message = str(m)
        self.status_code = c

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.__class__.__name__ + '/' + repr(self.to_dict())

    def to_dict(self):
        return {"message": self.message, "status": self.status_code}


def patch_dict(base, keys):
    for k in keys:
        if k not in base:
            base[k] = None


def check_account_content(h):
    global account_fields
    patch_dict(h, account_fields)


def check_container_content(h):
    global container_fields
    patch_dict(h, container_fields)


def acquire_lock_with_timeout(conn, lockname, acquire_timeout=10,
                              lock_timeout=10):
    identifier = str(uuid.uuid4())
    lockname = 'lock:' + lockname
    lock_timeout = int(math.ceil(lock_timeout))
    end = time.time() + acquire_timeout

    while time.time() < end:
        if conn.setnx(lockname, identifier):
            conn.expire(lockname, lock_timeout)
            return identifier
        elif not conn.ttl(lockname):
            conn.expire(lockname, lock_timeout)

        time.sleep(.001)
    return False


def release_lock(conn, lockname, identifier):
    pipe = conn.pipeline(True)
    lockname = 'lock:' + lockname

    while True:
        try:
            pipe.watch(lockname)
            if pipe.get(lockname) == identifier:
                pipe.multi()
                pipe.delete(lockname)
                pipe.execute()
                return True

            pipe.unwatch()
            break

        except redis.exceptions.WatchError:
            pass

    return False


class AccountBackend(object):
    def __init__(self, conf, conn=None):
        if not conf:
            conf = {}
        self.conf = conf
        if not conn:
            redis_host = conf.get('redis_host', '127.0.0.1')
            redis_port = int(conf.get('redis_port', '6379'))
            self.conn = redis.Redis(host=redis_host, port=redis_port)
        else:
            self.conn = conn

    def create_account(self, account_id):
        conn = self.conn
        account_id = account_id.lower()
        lock = acquire_lock_with_timeout(conn, 'account:' + account_id, 1)
        if not lock:
            return None

        if conn.hget('accounts:', account_id):
            return None

        pipeline = conn.pipeline(True)
        pipeline.hset('accounts:', account_id, 1)
        pipeline.hmset('account:%s' % account_id, {
            'id': account_id,
            'containers': 0,
            'bytes': 0,
            'ctime': time.time()
        })
        pipeline.execute()
        release_lock(conn, 'account:' + account_id, lock)
        return account_id

    def update_account(self, account_id, data):
        conn = self.conn
        if not account_id:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None

        conn.hmset('account:%s' % account_id, data)
        return account_id

    def info_account(self, account_id):
        conn = self.conn
        if not account_id:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None

        return conn.hgetall('account:%s' % account_id)

    def update_container(self, account_id, name, data):
        conn = self.conn
        if not account_id or not name:
            return None
        account_id = conn.hget('account:%s' % account_id, 'id')

        if not account_id:
            return None


        data.update({
            'name': name,
            'account_uid': account_id
        })

        conn.hmset('container:%s:%s' % (account_id, name), data)

        ct = {str(name): 0}

        conn.zadd('containers:%s' % account_id, **ct)

        return name

    def list_containers(self, account_id, page=1, count=100):
        conn = self.conn
        start = (page - 1) * count
        end = page * count - 1

        containers = conn.zrange('containers:%s' % account_id, start, end)
        pipeline = conn.pipeline(True)
        for container_id in containers:
            pipeline.hgetall('container:%s:%s' % (account_id, container_id))
        return pipeline.execute()

    def status(self):
        conn = self.conn
        account_count = conn.hlen('accounts:')
        return account_count