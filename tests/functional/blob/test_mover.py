# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

import random
from os import listdir
from mock import MagicMock as Mock
from os.path import join, exists
from oio.common.utils import GeneratorIO, cid_from_name
from oio.common.exceptions import ChunkException, Conflict, SpareChunkException
from oio.blob.mover import BlobMoverWorker
from oio.content.quality import get_distance
from tests.utils import BaseTestCase, random_str


class TestBlobMover(BaseTestCase):
    def setUp(self):
        super(TestBlobMover, self).setUp()
        self.container = "blob-mover-" + random_str(6)
        self.cid = cid_from_name(self.account, self.container)
        self.path = "blob-" + random_str(8)
        self.api = self.storage
        self.blob_client = self.api.blob_client

        self.api.container_create(self.account, self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, size=1
        )
        self.rawx_services = self.conscience.all_services("rawx")
        if len(chunks) >= len([s for s in self.rawx_services if s["score"] > 0]):
            self.skipTest(f"need at least {len(chunks) + 1} rawx to run")

        self.rawx_volumes = {}
        self.rawx_tags_loc = {}
        for rawx in self.rawx_services:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume
            self.rawx_tags_loc[service_id] = tags["tag.loc"]

        self.api.object_create(
            self.account, self.container, obj_name=self.path, data="chunk"
        )
        meta, self.chunks = self.api.object_locate(
            self.account, self.container, self.path
        )
        self.version = meta["version"]
        self.content_id = meta["id"]
        self.chunk_method = meta["chunk_method"]

    def tearDown(self):
        try:
            self.storage.container_flush(self.account, self.container)
            self.storage.container_delete(self.account, self.container)
        except Exception as exc:
            self.logger.info(
                "Failed to clean %s/%s: %s", self.account, self.container, exc
            )
        super(TestBlobMover, self).tearDown()

    def _chunk_path(self, chunk):
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume = self.rawx_volumes[volume_id]
        return volume + "/" + chunk_id[:3] + "/" + chunk_id

    def test_move_with_wrong_size(self):
        if not self.chunk_method.startswith("ec"):
            self.skipTest("Only works with EC")

        orig_chunk = random.choice(self.chunks)
        chunk_volume = orig_chunk["url"].split("/")[2]
        chunk_id = orig_chunk["url"].split("/")[3]

        mover = BlobMoverWorker(
            self.conf, None, self.rawx_volumes[chunk_volume], watchdog=self.watchdog
        )
        meta, stream = mover.blob_client.chunk_get(orig_chunk["url"])
        data = b"".join(stream)
        stream.close()
        data = data[:-1]
        del meta["chunk_hash"]
        wrong_stream = GeneratorIO(data)
        mover.blob_client.chunk_get = Mock(return_value=(meta, wrong_stream))

        self.assertRaises(
            (ChunkException, SpareChunkException),
            mover.chunk_move,
            self._chunk_path(orig_chunk),
            chunk_id,
        )

    def _get_volume_with_misplaced_chunks(self, chunks):
        """
        Check if created object has misplaced chunks and
        returns the list of locations volumes containing these misplaced
        chunks
        """
        locations = []
        for chunk in chunks:
            url = chunk["url"]
            volume_id = url.split("/", 3)[2]
            chunk_id = url.split("/", 3)[3]
            volume_path = self.rawx_volumes[volume_id]
            symlink_folder = join(volume_path, "non_optimal_placement", chunk_id[:3])
            is_misplaced = (
                any(f for f in listdir(symlink_folder) if chunk_id in f)
                if exists(symlink_folder)
                else False
            )
            if is_misplaced:
                locations.append(self.rawx_tags_loc[volume_id])
        return locations

    def _init_objects(self, misplaced_chunk, corrupt_data, extra_properties=False):
        # Objects having chunk to to another volume
        objects = {}
        object_with_misplaced = {}
        corrupted_objects = {}
        while not objects:  # To be sure to have chunks to move
            volume_dict = random.choice(self.rawx_services)
            volume = volume_dict["id"] or volume_dict["addr"]
            volume_path = self.rawx_volumes[volume]
            for i in range(10):
                object_name = "m_chunk-" + random_str(8)
                create_kwargs = {}
                if extra_properties:
                    create_kwargs["extra_properties"] = {"foo": "bar", "foo+2": "bar+2"}
                self.api.object_create(
                    self.account,
                    self.container,
                    obj_name=object_name,
                    data="chunk",
                    **create_kwargs,
                )
                _, chunks = self.api.object_locate(
                    self.account, self.container, object_name
                )
                for chunk in chunks:
                    chunk_volume = chunk["url"].split("/")[2]
                    chunk_id = chunk["url"].split("/")[3]
                    if chunk_volume == volume:
                        volumes_with_mc = self._get_volume_with_misplaced_chunks(chunks)
                        if volumes_with_mc:
                            object_with_misplaced.setdefault(object_name, []).extend(
                                volumes_with_mc
                            )
                        objects.setdefault(object_name, {}).update(
                            {chunk_id: chunk_volume}
                        )
                        if misplaced_chunk:
                            try:
                                # Create the symbolic link of the chunk
                                self.blob_client.tag_misplaced_chunk(
                                    [chunk["url"]], self.logger
                                )
                            except Conflict:
                                # The symlink already exists
                                pass
                        if corrupt_data:
                            if (i % 2) == 0:  # Corrupt data sometimes
                                # Corrupt the chunk
                                corrupted_data = b"chunk is dead"
                                with open(self._chunk_path(chunk), "wb") as fp:
                                    fp.write(corrupted_data)
                                corrupted_objects.setdefault(object_name, []).append(
                                    chunk_id
                                )
        return (
            volume,
            volume_path,
            objects,
            corrupted_objects,
            object_with_misplaced,
        )

    def _check_symlink(self, new_volume_path, volume_path, symlink_folder, chunk_id):
        """
        Check that a symlink exists in the new volume,
        but does not exist in the old one.
        """
        symlink_folder_path = join(new_volume_path, symlink_folder, chunk_id[:3])
        try:
            new_symlinks = [f for f in listdir(symlink_folder_path) if chunk_id in f]
        except FileNotFoundError:
            new_symlinks = []
        # Check if the symlink has been moved too
        symlink_folder_path = join(volume_path, symlink_folder, chunk_id[:3])
        try:
            old_symlinks = [f for f in listdir(symlink_folder_path) if chunk_id in f]
        except FileNotFoundError:
            old_symlinks = []
        if new_volume_path != volume_path:  # Able to move the chunk
            # Check if the old symlink has been removed
            self.assertEqual(len(old_symlinks), 0)
        self.assertEqual(len(new_symlinks), 1)

    def _test_local_mover(
        self,
        misplaced_chunk=False,
        corrupt_data=False,
        no_adjacent_services=False,
        extra_properties=False,
    ):
        if not self.chunk_method.startswith("ec"):
            self.skipTest("Only works with EC")
        (
            volume,
            volume_path,
            objects,
            corrupted_objects,
            object_with_misplaced,
        ) = self._init_objects(misplaced_chunk, corrupt_data, extra_properties)
        initial_location = self.rawx_tags_loc[volume]
        locked_svc = []
        # Stop adjacent services, so that mover chooses distant services.
        if no_adjacent_services:
            # Stop adjacent services, so that mover chooses distant services.
            # Lock rawx services on the selected host.
            # The objective is to be sure that the mover does not select spare chunks
            # on adjacent services.
            for rawx in self.rawx_services:
                if get_distance(rawx["tags"]["tag.loc"], initial_location) == 1:
                    rawx["score"] = 0
                    rawx["type"] = "rawx"
                    locked_svc.append(rawx)
            self._lock_services("rawx", locked_svc, wait=2.0)
            self._reload_proxy()
        mover = BlobMoverWorker(self.conf, None, volume_path, watchdog=self.watchdog)
        mover.process()
        if no_adjacent_services:
            # Unlock rawx services
            self.conscience.unlock_score(locked_svc)
            # wait until the services are unlocked
            self.wait_for_score(("rawx",), timeout=5.0, score_threshold=5)
        for object_name, chunks_to_move in objects.items():
            _, chunks = self.api.object_locate(
                self.account, self.container, object_name
            )
            for chunk in chunks:
                if extra_properties:
                    meta = self.api.blob_client.chunk_head(chunk["url"])
                    self.assertIn("extra_properties", meta)
                    self.assertDictEqual(
                        meta["extra_properties"],
                        {"Foo": "bar", "Foo+2": "bar+2"},
                    )
                chunk_id = chunk["url"].split("/")[3]
                chunk_volume = chunk["url"].split("/")[2]
                new_location = self.rawx_tags_loc[chunk_volume]
                if chunk_id in chunks_to_move:
                    new_volume_path = self.rawx_volumes[chunk_volume]
                    if (
                        object_name in corrupted_objects
                        and chunk_id in corrupted_objects[object_name]
                    ):
                        # Check that the chunk has been skipped
                        self.assertEqual(volume_path, new_volume_path)
                        self.assertEqual(
                            get_distance(initial_location, new_location), 0
                        )
                        continue
                    if no_adjacent_services:
                        if volume_path != new_volume_path:  # Able to move the chunk
                            # If the mover succeeded relocation of the chunk, it must
                            # be on a distant service.
                            self.assertGreater(
                                get_distance(initial_location, new_location), 1
                            )
                        else:
                            # No spare chunk found, chunk not relocated
                            self.assertEqual(
                                get_distance(initial_location, new_location), 0
                            )
                        continue
                    if object_name in object_with_misplaced and any(
                        loc
                        for loc in object_with_misplaced[object_name]
                        if get_distance(initial_location, loc) in (1, 0)
                    ):
                        if volume_path != new_volume_path:  # Able to move the chunk
                            # The location has been improved
                            # we did not move the data to adjacent services
                            self.assertGreater(
                                get_distance(initial_location, new_location), 1
                            )
                            continue
                    if volume_path != new_volume_path:  # Able to move the chunk
                        # Here we expect to move the chunk to a local location
                        self.assertEqual(
                            get_distance(initial_location, new_location), 1
                        )
                        if misplaced_chunk:
                            self._check_symlink(
                                new_volume_path,
                                volume_path,
                                mover.NON_OPTIMAL_DIR,
                                chunk_id,
                            )

    def test_local_mover(self):
        """Test of the local mover"""
        self._test_local_mover()

    def test_local_mover_with_misplaced_chunks(self):
        """Test if local mover knows how to handle misplaced symlink"""
        self._test_local_mover(misplaced_chunk=True)

    def test_local_mover_data_integrity_compromised(self):
        """Test if local mover skip compromised data"""
        self._test_local_mover(corrupt_data=True)

    def test_local_mover_no_adjacent_services(self):
        """Test if local mover fallback to distant services
        if adjacent services are  not available
        """
        self._test_local_mover(no_adjacent_services=True)

    def test_local_mover_extra_properties(self):
        """Test of the local mover with extra properties on object creation.
        Those extra properties are stored in chunks' extended attributes.
        """
        self._test_local_mover(extra_properties=True)
