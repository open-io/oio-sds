import unittest

from mock import MagicMock as Mock
from mock import patch

from oio.sds.event.agent import EventWorker


class TestEventWorker(unittest.TestCase):
    @patch('oio.sds.event.agent.ConscienceClient', Mock())
    @patch('oio.sds.event.agent.RdirClient', Mock())
    def setUp(self):
        context = Mock()
        conf = {'namespace': 'NS'}
        self.worker = EventWorker(conf, "test", context)

    def test_process_event(self):
        w = self.worker
        w.handle_container_destroy = Mock()
        w.handle_container_put = Mock()
        w.handle_container_update = Mock()
        w.handle_object_delete = Mock()
        w.handle_object_put = Mock()
        w.handle_reference_update = Mock()
        w.handle_chunk_put = Mock()
        w.handle_chunk_delete = Mock()
        w.handle_ping = Mock()

        event_types_handlers = [
                ('meta2.container.destroy', w.handle_container_destroy),
                ('meta2.container.create', w.handle_container_put),
                ('meta2.container.state', w.handle_container_update),
                ('meta2.content.new', w.handle_object_put),
                ('meta2.content.deleted', w.handle_object_delete),
                ('meta1.account.services', w.handle_reference_update),
                ('rawx.chunk.new', w.handle_chunk_put),
                ('rawx.chunk.delete', w.handle_chunk_delete),
                ('ping', w.handle_ping)
        ]

        for event_type, handler in event_types_handlers:
            event = {'event': event_type}
            self.assertEqual(w.process_event(event), True)
            handler.assert_called_once_with(event)

        self.assertEqual(w.process_event({'event': 'foo'}), True)

        w.handle_ping = Mock(side_effect=Exception('bar'))
        self.assertEqual(w.process_event({'event': 'ping'}), False)

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
