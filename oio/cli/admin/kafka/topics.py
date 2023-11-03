# Copyright (C) 2023 OVH SAS
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
# License along with this library.from cliff import lister


from enum import IntEnum
import yaml

from confluent_kafka import TopicCollection, Consumer
from confluent_kafka.admin import (
    AdminClient,
    NewTopic,
    NewPartitions,
    KafkaException,
    ConfigResource,
)
from oio.cli import Lister, ShowOne


class KafkaCommandMixinBase:
    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def admin_client(self):
        if not hasattr(self, "_kafka_admin_client") or not self._kafka_admin_client:
            self.logger.info("Instantiate admin Kafka client")
            conf = self.app.client_manager.sds_conf
            endpoint = conf.get("event-agent", "")

            if not endpoint.startswith("kafka://"):
                raise Exception("Endpoint is not a Kafka server")

            # Remove kafka:// prefix
            endpoint = endpoint[8:]
            # There is no way to redirect log messages. A PR has been created on Github
            # (https://github.com/confluentinc/confluent-kafka-python/pull/1674).
            # We should add `logger=self.logger` argument to constructor if this PR is
            # merged.
            self._kafka_admin_client = AdminClient(
                {
                    "bootstrap.servers": endpoint,
                },
            )
        return self._kafka_admin_client

    @property
    def consumer_client(self):
        if (
            not hasattr(self, "_kafka_consumer_client")
            or not self._kafka_consumer_client
        ):
            self.logger.info("Instantiate consumer client")
            conf = self.app.client_manager.sds_conf
            endpoint = conf.get("event-agent", "")

            if not endpoint.startswith("kafka://"):
                raise Exception("Endpoint is not a Kafka server")

            # Remove kafka:// prefix
            endpoint = endpoint[8:]

            self._kafka_consumer_client = Consumer(
                {
                    "bootstrap.servers": endpoint,
                },
                logger=self.logger,
            )
        return self._kafka_consumer_client

    def list_topics(self, exclude_internal=True):
        """List the topics declared on cluster"""
        topics = {}

        metadata = self.admin_client.list_topics()
        _topics = metadata.topics

        if _topics:
            futures = self.admin_client.describe_topics(
                TopicCollection([topic for topic in _topics.keys()]), request_timeout=10
            )

            for topic_name, future in futures.items():
                try:
                    topic = future.result()
                    # "_schemas" topic may not have is_internal flag set
                    if exclude_internal and (
                        topic.is_internal or topic.name == "_schemas"
                    ):
                        continue
                    topics[topic_name] = (None, topic)
                except KafkaException as exc:
                    self.logger.error(
                        "Unable to describe topic '%s', reason: %s",
                        topic_name,
                        str(exc),
                    )
                    topics[topic_name] = (exc, None)

        return topics

    def get_topics_details(self, topics):
        """Retrieve topics configuration options"""
        details = {}

        if topics:
            futures = self.admin_client.describe_configs(
                [ConfigResource(ConfigResource.Type.TOPIC, t) for t in topics]
            )

            for res, future in futures.items():
                name = res.name
                try:
                    conf = future.result()
                    details[name] = (None, conf)
                except KafkaException as exc:
                    self.logger.error(
                        "Unable to describe configuration for topic %s, reason: %s",
                        name,
                        str(exc),
                    )
                    details[name] = (exc, None)
        return details


class KafkaListTopics(KafkaCommandMixinBase, Lister):
    """List topics declared on cluster"""

    columns = ("topic", "partitions", "replica", "error")

    def get_parser(self, prog_name):
        parser = super(KafkaListTopics, self).get_parser(prog_name)

        parser.add_argument(
            "--include-internal", action="store_true", help="Include internal topics"
        )
        return parser

    def take_action(self, parsed_args):
        topics = self.list_topics(not parsed_args.include_internal)

        res = []

        for name, (error, topic) in topics.items():
            if error:
                res.append((name, "", "", str(error)))
                self.success = False
            else:
                res.append(
                    (
                        name,
                        len(topic.partitions),
                        len(topic.partitions[0].replicas),
                        "",
                    )
                )

        return self.columns, res


class KafkaTopicDetails(KafkaCommandMixinBase, ShowOne):
    """Get topic detailed information"""

    columns = ("name", "topic_id")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "topic",
            help="Name of the topic",
            metavar="<topic>",
        )

        return parser

    def take_action(self, parsed_args):
        client = self.admin_client

        data = client.list_topics(parsed_args.topic)
        topic = data.topics[parsed_args.topic]

        if topic.error:
            raise ValueError("Topic not found")

        # Get details on topic
        futures = client.describe_topics(TopicCollection([parsed_args.topic]))
        for name, future in futures.items():
            try:
                topic = future.result()
            except KafkaException as exc:
                self.logger.error(
                    "Unable to describe topic %s, reason: %s", name, str(exc)
                )
                self.success = False
                return
        res = [
            ("name", topic.name),
            ("internal", topic.is_internal),
            ("partitions", len(topic.partitions)),
            ("replicas", len(topic.partitions[0].replicas)),
        ]

        details = self.get_topics_details([parsed_args.topic])
        err, details = details.get(parsed_args.topic, (None, None))

        if err:
            self.success = False
            return

        for opt in details.values():
            res.append((opt.name, opt.value))

        return [r[0] for r in res], [r[1] for r in res]


class Actions(IntEnum):
    DELETE = 1
    CREATE = 2
    PARTITION = 3
    ALTER_CONF = 4


class TopicPipeline:
    def __init__(self, name):
        self.name = name

        self._actions = {}
        self._results = {}

    def register_action(self, action, payload):
        if action in self._actions:
            raise ValueError(f"'{action}' already registered for topic '{self.name}'")
        self._actions[action] = payload

    def set_action_result(self, action, error):
        if action not in self._actions:
            raise ValueError(f"'{action}' not registered for topic '{self.name}'")
        self._results[action] = error

    def has_action(self, action):
        return action in self._actions

    def get_payload(self, action):
        return self._actions[action]

    @property
    def has_error(self):
        for res in self._results.values():
            if res:
                return True
        return False

    def status(self):
        actions_status = []
        actions = [a for a in self._actions]
        actions.sort()
        for action in actions:
            status = "Success"
            if action not in self._results:
                status = "Skipped"
            elif self._results[action]:
                err = self._results[action]
                status = f"Error: {str(err)}"
            actions_status.append((self.name, action.name, status))

        return actions_status


class KafkaCreateTopics(KafkaCommandMixinBase, Lister):
    """Update cluster topics configuration according to configuration file"""

    columns = ("topic", "action", "status")

    def get_parser(self, prog_name):
        parser = super(KafkaCreateTopics, self).get_parser(prog_name)

        parser.add_argument(
            "schema",
            metavar="<schema>",
            help="Yaml file describing topics configuration",
        )

        parser.add_argument(
            "--delete",
            action="store_true",
            help="Delete topics not present in configuration",
        )

        parser.add_argument(
            "--reset",
            action="store_true",
            help="Recreate all topics",
        )

        return parser

    def _delete_topics(self, payloads):
        delete_topics = [p["name"] for p in payloads]
        return self.admin_client.delete_topics(delete_topics)

    def _create_topics(self, payloads):
        return self.admin_client.create_topics(
            [
                NewTopic(
                    p["name"],
                    num_partitions=p["partitions"],
                    replication_factor=p["replicas"],
                )
                for p in payloads
            ]
        )

    def _partition_topics(self, payloads):
        new_parts = [NewPartitions(p["name"], p["partitions"]) for p in payloads]
        return self.admin_client.create_partitions(new_parts, validate_only=False)

    def _alter_config(self, payloads):
        resources = []
        for payload in payloads:
            resource = ConfigResource(ConfigResource.Type.TOPIC, payload["name"])
            for key, value in payload["options"].items():
                resource.set_config(key, value)
            resources.append(resource)
        return self.admin_client.alter_configs(resources)

    def _process_pipelines(self, pipelines):
        actions = {
            Actions.DELETE: self._delete_topics,
            Actions.CREATE: self._create_topics,
            Actions.PARTITION: self._partition_topics,
            Actions.ALTER_CONF: self._alter_config,
        }

        for action, func in actions.items():
            self.logger.info("Processing action: %s", action.name)
            data = {}
            for pipeline in pipelines:
                if pipeline.has_error:
                    self.logger.warn(
                        "Skipping action '%s' for topic '%s' due to prior error",
                        action.name,
                        pipeline.name,
                    )
                    continue

                if not pipeline.has_action(action):
                    continue

                data[pipeline.name] = pipeline
            if not data:
                continue
            futures = func([p.get_payload(action) for p in data.values()])

            for name, future in futures.items():
                if isinstance(name, ConfigResource):
                    name = name.name
                err = None
                try:
                    future.result()
                except KafkaException as exc:
                    self.logger.error(
                        "Failed to process '%s' on topic '%s', reason: %s",
                        action.name,
                        name,
                        str(exc),
                    )
                    err = exc
                    self.success = False
                data[name].set_action_result(action, err)

    def _load_topics_from_config(self, schema):
        topics_to_process = {}
        with open(schema, "r", encoding="utf8") as file:
            schema = yaml.safe_load(file)
            default_options = schema.get("options", {})
            default_replication = schema.get("replication", 1)
            default_partitions = schema.get("partitions", 1)

            topics = schema.get("topics", [])
            for topic_name, topic_details in topics.items():
                if topic_details is None:
                    topic_details = {}

                options = default_options.copy()
                options.update(topic_details.get("options", {}))
                topics_to_process[topic_name] = {
                    "name": topic_name,
                    "options": options,
                    "partitions": topic_details.get("partitions", default_partitions),
                    "replication": topic_details.get(
                        "replication", default_replication
                    ),
                }
        return topics_to_process

    def take_action(self, parsed_args):
        # Get topics and options from conf
        topics_to_process = self._load_topics_from_config(parsed_args.schema)
        self.logger.info(
            "Topics to declared %s", ", ".join([t for t in topics_to_process])
        )

        # List topics declared on cluster
        remote_topics = self.list_topics(exclude_internal=True)
        errors = [n for n, (e, _) in remote_topics.items() if e]

        remote_details = self.get_topics_details([t for t in remote_topics])
        errors.extend([n for n, (e, _) in remote_details.items() if e])

        if errors:
            raise RuntimeError("Failed to retrieve all topics info")

        # Remove error field from tuple
        remote_topics = {k: t for k, (_, t) in remote_topics.items() if t}
        remote_details = {k: d for k, (_, d) in remote_details.items() if d}
        self.logger.info("Existing topics: %s", ", ".join(remote_topics))

        # Build pipelines
        pipelines = {}

        for name, topic in topics_to_process.items():
            remote_topic = remote_topics.get(name)
            remote_options = remote_details.get(name, {})

            pipeline = pipelines.setdefault(name, TopicPipeline(name))
            # Create
            if remote_topic is None or parsed_args.reset:
                pipeline.register_action(
                    Actions.CREATE,
                    {
                        "name": name,
                        "replicas": topic.get("replicas", 1),
                        "partitions": topic.get("partitions", 1),
                    },
                )
            # Partition
            elif remote_topic:
                if topic.get("partitions", 1) > len(
                    remote_topic.partitions
                ) and not pipeline.has_action(Actions.CREATE):
                    pipeline.register_action(
                        Actions.PARTITION,
                        {
                            "name": name,
                            "partitions": topic.get("partitions", 1),
                        },
                    )
            # Alter config
            options = {}
            same_options = {}
            for key, value in topic.get("options", {}).items():
                remote_value = remote_options.get(key)
                if (
                    not parsed_args.reset
                    and remote_value
                    and remote_value.value == str(value)
                ):
                    same_options[key] = value
                else:
                    options[key] = value
            if options:
                options.update(same_options)
                self.logger.info("Update config of topic '%s' with: %s", name, options)
                pipeline.register_action(
                    Actions.ALTER_CONF,
                    {
                        "name": name,
                        "options": options,
                    },
                )
        # Delete
        if parsed_args.delete or parsed_args.reset:
            for name in remote_topics:
                if name in topics_to_process and not parsed_args.reset:
                    continue
                pipeline = pipelines.setdefault(name, TopicPipeline(name))
                pipeline.register_action(Actions.DELETE, {"name": name})

        self._process_pipelines(pipelines.values())

        # Build process report
        res = []
        for pipeline in pipelines.values():
            res.extend(pipeline.status())

        return self.columns, res
