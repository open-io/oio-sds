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

    def _prepare_test(
        self,
        is_deletion=False,
        is_update=False,
        real_delete_version=False,
    ):
        account = self.account_from_env()
        obj = "test-repli-catch-up-" + random_str(3)
        src_container = "container-" + random_str(3)
        dst_container = src_container + "-dst"
        self.bucket_client.bucket_create(src_container, account)
        self.openio(f"container create {src_container} --bucket-name {src_container}")
        self.openio(f"container set --versioning -1 {src_container}")
        self.clean_later(src_container, account)
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
                    "Destination": {"Bucket": f"arn:aws:s3:::{dst_container}"},
                }
            },
            "replications": {f"arn:aws:s3:::{dst_container}": ["ReplicationRule-1"]},
            "deletions": {f"arn:aws:s3:::{dst_container}": ["ReplicationRule-1"]},
            "use_tags": False,
        }
        props = {"X-Container-Sysmeta-S3Api-Replication": json.dumps(repli_conf)}
        self.storage.container_set_properties(account, src_container, properties=props)
        reqid = request_id("create-obj-")
        replication_status = "COMPLETED" if is_update else "PENDING"
        # Create an object
        _, _, _, obj_meta = self.storage.object_create_ext(
            account,
            src_container,
            obj_name=obj,
            data=b"Something",
            reqid=reqid,
            replication_destinations=dst_container,
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
        self.assertEqual(dst_container, event.repli["destinations"])
        self.assertEqual("repliRecoveryId", event.repli["replicator_id"])
        self.assertEqual("repliRecoveryRole", event.repli["src_project_id"])
        if is_deletion:
            reqid = request_id("create-marker-")
            self.storage.object_delete(
                account,
                src_container,
                obj=obj,
                reqid=reqid,
                replication_destinations=dst_container,
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
                reqid = request_id("delete-obj-")
                self.storage.object_delete(
                    account,
                    src_container,
                    obj=obj,
                    reqid=reqid,
                    version=obj_version,
                )
                event = self.wait_for_kafka_event(
                    reqid=reqid,
                    types=(EventTypes.CONTENT_DELETED,),
                )
                self.assertIsNotNone(event)

        return account, src_container, dst_container, obj

    def _check_event(self, event_to_check, dst_container, is_deletion, is_update):
        # assertStartsWith available in Python 3.14+
        self.assertTrue(event_to_check.reqid.startswith("catch-up-"))
        self.assertEqual(dst_container, event_to_check.repli["destinations"])
        self.assertEqual("repliRecoveryId", event_to_check.repli["replicator_id"])
        self.assertEqual("repliRecoveryRole", event_to_check.repli["src_project_id"])
        found = False
        print(event_to_check.data)
        for d in event_to_check.data:
            deleted = d.get("deleted")
            if deleted is not None:
                if is_deletion and not is_update:
                    self.assertTrue(true_value(deleted))
                    break
                self.assertFalse(true_value(deleted))
            key = d.get("key")
            if key and key == "x-object-sysmeta-s3api-acl":
                self.assertEqual("myuseracls", d["value"])
                found = True
                break
        if not is_deletion:
            self.assertTrue(found)

    def _test_recovery_tool(
        self,
        is_deletion=False,
        is_update=False,
        with_invalid_option=False,
        real_delete_version=False,
    ):
        account, src_container, dst_container, obj = self._prepare_test(
            is_deletion, is_update, real_delete_version
        )
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
                    f"replication catch-up {src_container} {option}", ""
                ),
            )
            return
        self.openio(
            f"replication catch-up {src_container} {option}",
            coverage="",
        )

        event = self.wait_for_kafka_event(
            types=event_types,
            fields={
                "account": account,
                "user": src_container,
            },
            origin="s3-replication-recovery",
            kafka_consumer=self._cls_replication_consumer,
            timeout=30,
        )
        if not real_delete_version:
            self.assertIsNotNone(event)
            self._check_event(event, dst_container, is_deletion, is_update)
        else:
            # Only delete marker exists, we should not recreate any events
            self.assertIsNone(event)

        # In case of deletion, the "valid" object also needs to be replicated.
        if is_deletion and not real_delete_version:
            event = self.wait_for_kafka_event(
                types=event_types,
                fields={
                    "account": account,
                    "user": src_container,
                },
                origin="s3-replication-recovery",
                kafka_consumer=self._cls_replication_consumer,
                timeout=30 if not is_update else 10,
            )
            if is_update:
                # If we ask for an update on an object with a delete-marker,
                # we expect only one event (already checked above)
                self.assertIsNone(event)
            else:
                self.assertIsNotNone(event)
                self._check_event(event, dst_container, False, is_update)

    def test_replication_catch_up_ignores_markers(self):
        self._test_recovery_tool(is_deletion=True, is_update=True)

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
