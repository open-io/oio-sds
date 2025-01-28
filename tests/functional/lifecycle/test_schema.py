# Copyright (C) 2025 OVH SAS
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

from oio.api.object_storage import ObjectStorageApi
from oio.container.lifecycle import ContainerLifecycle, LifecycleConfigurationInvalid
from tests.utils import BaseTestCase


class TestLifecycleSchema(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.api = ObjectStorageApi(self.ns, pool_manager=self.http_pool)
        self.container_lc = ContainerLifecycle(self.api, "my-account", "my-container")

    def test_invalid_schema(self):
        # Empty
        self.assertRaises(LifecycleConfigurationInvalid, self.container_lc.load, {})

        # Missing extra fields aka accelerator
        self.assertRaises(
            LifecycleConfigurationInvalid, self.container_lc.load, {"Rules": {}}
        )

        # Missing "date" and "days" fields in expiration accelerator
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {},
                "_schema_version": 1,
                "_expiration_rules": {},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # Unsuported Tags in filter
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "1": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                            "Tags": [
                                {"Key": "", "Value": ""},
                            ],
                        },
                        "Expiration": {"0": {"Days": 1}},
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # Empty internal rule identifier
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                            "Tag": [
                                {"Key": "key1", "Value": ""},
                            ],
                        },
                        "Expiration": {"0": {"Days": 1}},
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # Empty Key in Tag
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "1": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                            "Tag": [
                                {"Key": "", "Value": ""},
                            ],
                        },
                        "Expiration": {"0": {"Days": 1}},
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # Too many expirations
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "1": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                        },
                        "Expiration": {"0": {"Days": 1}, "1": {"Days": 1}},
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # No abort mpu
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "0": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                        },
                        "AbortIncompleteMultipartUpload": {},
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # No abort mpu
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "0": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                        },
                        "AbortIncompleteMultipartUpload": {
                            "0": {},
                        },
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # Invalid abort mpu
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "0": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                        },
                        "AbortIncompleteMultipartUpload": {
                            "0": {},
                        },
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )

        # Too many abort mpu
        self.assertRaises(
            LifecycleConfigurationInvalid,
            self.container_lc.load,
            {
                "Rules": {
                    "0": {
                        "ID": "Rule-1",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "foo",
                        },
                        "AbortIncompleteMultipartUpload": {
                            "0": {"DaysAfterInitiation": 1},
                            "1": {"DaysAfterInitiation": 1},
                        },
                    }
                },
                "_schema_version": 1,
                "_expiration_rules": {"days": [], "date": []},
                "_transition_rules": {"days": [], "date": []},
                "_delete_marker_rules": [],
                "_abort_mpu_rules": [],
                "_non_current_expiration_rules": [],
                "_non_current_transition_rules": [],
            },
        )
