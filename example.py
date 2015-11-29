#!/usr/bin/env python

import rabbit
import msgpack


AMQP_BROKER_HOST = ""
AMQP_BROKER_PORT = 5672
AMQP_BROKER_VHOST = ""
AMQP_BROKER_USER = ""
AMQP_BROKER_PASSWORD = ""

conn = rabbit.Connection()
conn.open(AMQP_BROKER_HOST, AMQP_BROKER_PORT)
conn.login(AMQP_BROKER_VHOST, 0, AMQP_BROKER_USER, AMQP_BROKER_PASSWORD)
conn.open_channel(1)
conn.declare_exchange(1, "queuename", "direct")
conn.declare_queue(1, "queuename")
conn.bind_queue(1, "queuename", "queuename", "queuename")
conn.consume(1, "queuename")

publish_conn = rabbit.Connection()
publish_conn.open(AMQP_BROKER_HOST, AMQP_BROKER_PORT)
publish_conn.login(AMQP_BROKER_VHOST, 0, AMQP_BROKER_USER, AMQP_BROKER_PASSWORD)
publish_conn.open_channel(1)
publish_conn.declare_exchange(1, "results", "direct")

while True:
    envelope = conn.consume_message()
    if envelope.message.properties.content_type == "application/x-msgpack":
        gc.disable()  # prevent GC being triggered by msgpack decoding
        decoded_body = msgpack.unpackb(envelope.message.body, encoding='utf-8', use_list=False)
        gc.enable()
        conn.ack(1, envelope.delivery_tag)

        # do something with decoded_body

        # publish something, maybe result of operation
        props = rabbit.Properties(content_type="application/x-msgpack", delivery_mode=1)
        body = msgpack.packb(payload)
        if len(body) > 8192:
            # example of compressing large message bodies
            from bz2 import compress
            body = compress(body)
            props.content_encoding = "bzip2"
        publish_conn.publish(1, "results", envelope.message.properties.reply_to, body, props)
    else:
        log.warning("Unexpected content-type: %s", envelope.message.properties.content_type)

