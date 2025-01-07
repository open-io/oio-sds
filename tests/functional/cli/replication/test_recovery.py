# Copyright (C) 2024-2025 OVH SAS
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

import json

from oio.common.easy_value import true_value
from oio.common.kafka import DEFAULT_REPLICATION_TOPIC
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ReplicationRecoveryTest(CliTestCase):
    """Functional tests for replication recovery."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._cls_replication_consumer = cls._register_consumer(
            topic=DEFAULT_REPLICATION_TOPIC
        )

    def setUp(self):
        super(ReplicationRecoveryTest, self).setUp()
        self.wait_for_score(("rawx", "meta2"), score_threshold=1, timeout=5.0)

    def _test_recovery_tool(
        self, is_deletion=False, is_update=False, with_invalid_option=False
    ):
        account = self.account_from_env()
        obj = "test-repli-recovery" + random_str(6)
        container_src = "container" + random_str(6) + "-src"
        container_dst = "container" + random_str(6) + "-dst"
        self.bucket_client.bucket_create(container_src, account)
        self.openio(f"container create {container_src} --bucket-name {container_src}")
        self.openio(f"container set --versioning -1 {container_src}")
        self.clean_later(container_src, account)
        # Add replication conf to the source
        repli_conf = {
            "role": "arn:aws:iam::repliRecoveryRole:role/repliRecoveryId",
            "rules": {
                "ReplicationRule-1": {
                    "ID": "ReplicationRule-1",
                    "Priority": 1,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {},
                    "Destination": {"Bucket": f"arn:aws:s3:::{container_dst}"},
                }
            },
            "replications": {f"arn:aws:s3:::{container_dst}": ["ReplicationRule-1"]},
            "deletions": {f"arn:aws:s3:::{container_dst}": ["ReplicationRule-1"]},
            "use_tags": False,
        }
        props = {"X-Container-Sysmeta-S3Api-Replication": json.dumps(repli_conf)}
        self.storage.container_set_properties(account, container_src, properties=props)
        reqid = request_id()
        replication_status = "COMPLETED" if is_update else "PENDING"
        # Create an object
        self.storage.object_create_ext(
            account,
            container_src,
            obj_name=obj,
            data=b"Something",
            reqid=reqid,
            replication_destinations=container_dst,
            replication_replicator_id="repliRecoveryId",
            replication_role_project_id="repliRecoveryRole",
            properties={
                "x-object-sysmeta-s3api-acl": "myuseracls",
                "x-object-sysmeta-s3api-replication-status": replication_status,
                "x-object-transient-sysmeta-myprop": "toto",
            },
        )
        event = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_NEW,),
        )
        self.assertIsNotNone(event)
        self.assertEqual(container_dst, event.repli["destinations"])
        self.assertEqual("repliRecoveryId", event.repli["replicator_id"])
        self.assertEqual("repliRecoveryRole", event.repli["src_project_id"])
        if is_deletion:
            reqid = request_id()
            self.storage.object_delete(
                account,
                container_src,
                obj=obj,
                reqid=reqid,
                replication_destinations=container_dst,
                replication_replicator_id="repliRecoveryId",
                replication_role_project_id="repliRecoveryRole",
                properties={
                    "x-object-sysmeta-s3api-replication-status": "PENDING",
                },
            )
            event = self.wait_for_kafka_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_NEW,),
            )
            self.assertIsNotNone(event)
            for d in event.data:
                deleted = d.get("deleted")
                if deleted is not None:
                    if is_deletion:
                        self.assertTrue(true_value(deleted))
                    else:
                        self.assertFalse(true_value(deleted))
                    break
        option = "--pending"
        event_types = (EventTypes.CONTENT_NEW,)
        if is_update:
            option = "--only-metadata"
            event_types = (EventTypes.CONTENT_UPDATE,)
        if with_invalid_option:
            option = "--pending --only-metadata"
            self.assertRaisesRegex(
                CommandFailed,
                "Cannot use both pending and only-metadata options at the same time",
                lambda: self.openio(
                    f"replication recovery {container_src} {option}", ""
                ),
            )
            return
        self.openio(
            f"replication recovery {container_src} {option}",
            coverage="",
        )
        event = self.wait_for_kafka_event(
            types=event_types,
            fields={
                "account": account,
                "user": container_src,
            },
            origin="s3-replication-recovery",
            kafka_consumer=self._cls_replication_consumer,
            timeout=60,
        )
        self.assertIsNotNone(event)
        self.assertEqual(container_dst, event.repli["destinations"])
        self.assertEqual("repliRecoveryId", event.repli["replicator_id"])
        self.assertEqual("repliRecoveryRole", event.repli["src_project_id"])
        self.assertIsNotNone(event)
        found = False
        for d in event.data:
            deleted = d.get("deleted")
            if deleted is not None:
                if is_deletion:
                    self.assertTrue(true_value(deleted))
                    break
                else:
                    self.assertFalse(true_value(deleted))
            key = d.get("key")
            if key and key == "x-object-sysmeta-s3api-acl":
                self.assertEqual("myuseracls", d["value"])
                found = True
                break
        if not is_deletion:
            self.assertTrue(found)

    def test_replication_recovery_content_new(self):
        self._test_recovery_tool()

    def test_replication_recovery_content_delete(self):
        self._test_recovery_tool(is_deletion=True)

    def test_replication_recovery_content_update(self):
        self._test_recovery_tool(is_update=True)

    def test_replication_recovery_content_invalid_option(self):
        self._test_recovery_tool(with_invalid_option=True)
