import unittest

from mock import MagicMock as Mock
from mock import patch

from oio.sds.event.agent import EventWorker


class TestEventWorker(unittest.TestCase):
    def setUp(self):
        context = Mock()
        with patch('oio.sds.event.agent.ConscienceClient', new=Mock()):
            self.worker = EventWorker({}, context)

    def test_process_event(self):
        self.worker.handle_container_destroy = Mock()
        self.worker.handle_container_put = Mock()
        self.worker.handle_container_update = Mock()
        self.worker.handle_object_delete = Mock()
        self.worker.handle_object_put = Mock()

        event = {"event": "meta2.container.destroy"}
        self.worker.process_event(event)
        self.worker.handle_container_destroy.assert_called_once_with(event)

        event = {"event": "meta2.container.create"}
        self.worker.process_event(event)
        self.worker.handle_container_put.assert_called_once_with(event)

        event = {"event": "meta2.container.state"}
        self.worker.process_event(event)
        self.worker.handle_container_update.assert_called_once_with(event)

        event = {"event": "meta2.content.new"}
        self.worker.process_event(event)
        self.worker.handle_object_put.assert_called_once_with(event)

        event = {"event": "meta2.content.deleted"}
        self.worker.process_event(event)
        self.worker.handle_object_delete.assert_called_once_with(event)

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
             },
            {"type": "chunks",
             "id": "http://127.0.0.1:5000/CCCCCC",
             "hash": "0000000000000000000000000000000",
             "size": 1
             }
        ]}
        self.worker.session.delete = Mock()
        self.worker.handle_object_delete(event)
        for chunk in event.get('data'):
            self.worker.session.delete.assert_any_call(chunk.get('id'))
