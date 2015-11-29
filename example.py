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

while True:
    envelope = conn.consume_message()
    if envelope.message.properties.content_type == "application/x-msgpack":
        gc.disable()  # prevent GC being triggered by msgpack decoding
        decoded_body = msgpack.unpackb(envelope.message.body, encoding='utf-8', use_list=False)
        gc.enable()
        conn.ack(1, envelope.delivery_tag)
        # do something with decoded_body
    else:
        log.warning("Unexpected content-type: %s", envelope.message.properties.content_type)

