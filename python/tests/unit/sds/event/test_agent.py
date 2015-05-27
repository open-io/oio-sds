import unittest

from mock import MagicMock as Mock
from mock import patch
from oio.sds.event.agent import EventWorker


class TestEventWorker(unittest.TestCase):
    def setUp(self):
        context = Mock()
        self.worker = EventWorker(None, context)

    def test_process_event(self):
        self.worker.handle_container_destroy = Mock()
        self.worker.handle_container_put = Mock()
        self.worker.handle_container_update = Mock()
        self.worker.handle_object_delete = Mock()
        self.worker.handle_object_put = Mock()

        event = {"event": "meta2.destroy"}
        self.worker.process_event(event)
        self.worker.handle_container_destroy.assert_called_once(event)

        event = {"event": "meta2.create"}
        self.worker.process_event(event)
        self.worker.handle_container_put.assert_called_once(event)

        event = {"event": "meta2.container.state"}
        self.worker.process_event(event)
        self.worker.handle_container_update.assert_called_once_with(event)

        event = {"event": "meta2.content.new"}
        self.worker.process_event(event)
        self.worker.handle_object_put.assert_called_once(event)

        event = {"event": "meta2.content.deleted"}
        self.worker.process_event(event)
        self.worker.handle_object_delete.assert_called_once(event)

    def test_object_delete_handler(self):

        event = {"data": [
            {"type": "chunks",
             "id": "http://127.0.0.1:5000/AAAAAA",
             "hash": "00000000000000000000000000000000",
             "size": 1
            },
            {"type": "chunks",
             "id": "http://127.0.0.1:5000/BBBBBB",
             "hash": "0000000000000000000000000000000",
             "size": 1
            }
        ]}
        with patch('oio.sds.event.agent.requests', new=Mock()) as requests:
            self.worker.handle_object_delete(event)
            for chunk in event.get('data'):
                requests.delete.assert_any_call(chunk.get('id'))
