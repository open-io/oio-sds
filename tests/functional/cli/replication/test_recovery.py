# Copyright (C) 2024-2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import json
import time
from datetime import datetime

from oio.common.easy_value import true_value
from oio.common.kafka import DEFAULT_REPLICATION_TOPIC
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ReplicationCatchUpTest(CliTestCase):
    """Functional tests for replication catch-up."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._cls_replication_consumer = cls._register_consumer(
            topic=DEFAULT_REPLICATION_TOPIC
        )

    def setUp(self):
        super().setUp()
        self.wait_for_score(("rawx", "meta2"), score_threshold=1, timeout=5.0)

    def _test_recovery_tool(
        self,
        is_deletion=False,
        is_update=False,
        with_invalid_option=False,
        real_delete_version=False,
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
        _, _, _, obj_meta = self.storage.object_create_ext(
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
        obj_version = obj_meta["version"]
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

            if real_delete_version:
                # Now that delete marker is created, delete the version
                reqid = request_id()
                self.storage.object_delete(
                    account,
                    container_src,
                    obj=obj,
                    reqid=reqid,
                    version=obj_version,
                )
                event = self.wait_for_kafka_event(
                    reqid=reqid,
                    types=(EventTypes.CONTENT_DELETED,),
                )
                self.assertIsNotNone(event)

        option = "--pending"
        event_types = (EventTypes.CONTENT_NEW,)
        if is_update:
            option = "--only-metadata"
            event_types = (EventTypes.CONTENT_UPDATE,)
        time.sleep(1)
        until_date = int(datetime.timestamp(datetime.now()))
        option += f" --until {until_date} --do-not-use-marker"
        if with_invalid_option:
            option = "--pending --only-metadata --do-not-use-marker"
            self.assertRaisesRegex(
                CommandFailed,
                r"argument .+ not allowed with argument .+",
                lambda: self.openio(
                    f"replication catch-up {container_src} {option}", ""
                ),
            )
            return
        self.openio(
            f"replication catch-up {container_src} {option}",
            coverage="",
        )

        def _check_event(event_to_check, is_deletion):
            self.assertIsNotNone(event_to_check)
            self.assertEqual(container_dst, event_to_check.repli["destinations"])
            self.assertEqual("repliRecoveryId", event_to_check.repli["replicator_id"])
            self.assertEqual(
                "repliRecoveryRole", event_to_check.repli["src_project_id"]
            )
            found = False
            for d in event_to_check.data:
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

        event = self.wait_for_kafka_event(
            types=event_types,
            fields={
                "account": account,
                "user": container_src,
            },
            origin="s3-replication-recovery",
            kafka_consumer=self._cls_replication_consumer,
            timeout=30,
        )
        if not real_delete_version:
            _check_event(event, is_deletion)
        else:
            # Only delete marker exists, we should not recreate any events
            self.assertIsNone(event)

        # In case of deletion, the "valid" object also needs to be recovered.
        if is_deletion and not real_delete_version:
            event = self.wait_for_kafka_event(
                types=event_types,
                fields={
                    "account": account,
                    "user": container_src,
                },
                origin="s3-replication-recovery",
                kafka_consumer=self._cls_replication_consumer,
                timeout=30,
            )
            _check_event(event, False)

    def test_replication_recovery_content_new(self):
        self._test_recovery_tool()

    def test_replication_recovery_content_delete(self):
        self._test_recovery_tool(is_deletion=True)

    def test_replication_recovery_content_delete_no_events(self):
        # Run recovery tool only on a delete marker (no events should be created)
        self._test_recovery_tool(is_deletion=True, real_delete_version=True)

    def test_replication_recovery_content_update(self):
        self._test_recovery_tool(is_update=True)

    def test_replication_recovery_content_invalid_option(self):
        self._test_recovery_tool(with_invalid_option=True)
