rabbitmq
========

Python bindings to librabbitmq using CFFI

This is fairly rudimentary so far but does allow using librabbitmq on Python 3 to a basic degree, which was my primary motivation for this work.

Currently tested against librabbitmq 0.8.0 on Python 3.6 and 2.7. It is in production on Python 3.6 on two fairly heavily-loaded message queues.

Available [on PyPI](https://pypi.python.org/pypi/rabbitmq), just `pip install rabbitmq`.

Proper documentation coming soon. Example usage:

```python
import rabbitmq

conn = rabbitmq.Connection()
conn.open(AMQP_BROKER_HOST, AMQP_BROKER_PORT)
conn.login(AMQP_BROKER_VHOST, 0, AMQP_BROKER_USER, AMQP_BROKER_PASSWORD)
conn.open_channel(1)
conn.declare_exchange(1, "queuename", "direct")
conn.declare_queue(1, "queuename")
conn.bind_queue(1, "queuename", "queuename", "queuename")
conn.consume(1, "queuename")

publish_conn = rabbitmq.Connection()
publish_conn.open(AMQP_BROKER_HOST, AMQP_BROKER_PORT)
publish_conn.login(AMQP_BROKER_VHOST, 0, AMQP_BROKER_USER, AMQP_BROKER_PASSWORD)
publish_conn.open_channel(1)
publish_conn.declare_exchange(1, "exchangename", "direct")

while True:
    envelope = conn.consume_message()
    conn.ack(1, envelope.delivery_tag)

    props = rabbitmq.Properties(content_type="...", delivery_mode=1)
    body = b"..."
    if len(body) > 8192:
        # example of compressing large message bodies
        from bz2 import compress
        body = compress(body)
        props.content_encoding = "bzip2"
    publish_conn.publish(1, "exchangename", envelope.message.properties.reply_to, body, props)
```
