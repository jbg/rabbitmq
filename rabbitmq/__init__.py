# Copyright 2016-2017 Jasper Bryant-Greene
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from cffi import FFI

_ffi = FFI()

_ffi.cdef("""
    #define AMQP_DEFAULT_FRAME_SIZE ...
    #define AMQP_DEFAULT_MAX_CHANNELS ...
    #define AMQP_DEFAULT_HEARTBEAT ...

    #define AMQP_BASIC_CONTENT_TYPE_FLAG ...
    #define AMQP_BASIC_CONTENT_ENCODING_FLAG ...
    #define AMQP_BASIC_HEADERS_FLAG ...
    #define AMQP_BASIC_DELIVERY_MODE_FLAG ...
    #define AMQP_BASIC_PRIORITY_FLAG ...
    #define AMQP_BASIC_CORRELATION_ID_FLAG ...
    #define AMQP_BASIC_REPLY_TO_FLAG ...
    #define AMQP_BASIC_EXPIRATION_FLAG ...
    #define AMQP_BASIC_MESSAGE_ID_FLAG ...
    #define AMQP_BASIC_TIMESTAMP_FLAG ...
    #define AMQP_BASIC_TYPE_FLAG ...
    #define AMQP_BASIC_USER_ID_FLAG ...
    #define AMQP_BASIC_APP_ID_FLAG ...
    #define AMQP_BASIC_CLUSTER_ID_FLAG ...

    typedef struct amqp_bytes_t_ {
        size_t len;
        void * bytes;
    } amqp_bytes_t;

    typedef enum amqp_status_enum_ {
        AMQP_STATUS_OK =                         0x0,
        AMQP_STATUS_NO_MEMORY =                 -0x0001,
        AMQP_STATUS_BAD_AMQP_DATA =             -0x0002,
        AMQP_STATUS_UNKNOWN_CLASS =             -0x0003,
        AMQP_STATUS_UNKNOWN_METHOD =            -0x0004,
        AMQP_STATUS_HOSTNAME_RESOLUTION_FAILED= -0x0005,
        AMQP_STATUS_INCOMPATIBLE_AMQP_VERSION = -0x0006,
        AMQP_STATUS_CONNECTION_CLOSED =         -0x0007,
        AMQP_STATUS_BAD_URL =                   -0x0008,
        AMQP_STATUS_SOCKET_ERROR =              -0x0009,
        AMQP_STATUS_INVALID_PARAMETER =         -0x000A,
        AMQP_STATUS_TABLE_TOO_BIG =             -0x000B,
        AMQP_STATUS_WRONG_METHOD =              -0x000C,
        AMQP_STATUS_TIMEOUT =                   -0x000D,
        AMQP_STATUS_TIMER_FAILURE =             -0x000E,
        AMQP_STATUS_HEARTBEAT_TIMEOUT =         -0x000F,
        AMQP_STATUS_UNEXPECTED_STATE =          -0x0010,
        AMQP_STATUS_TCP_ERROR =                 -0x0100,
        AMQP_STATUS_TCP_SOCKETLIB_INIT_ERROR =  -0x0101,
        AMQP_STATUS_SSL_ERROR =                 -0x0200,
        AMQP_STATUS_SSL_HOSTNAME_VERIFY_FAILED= -0x0201,
        AMQP_STATUS_SSL_PEER_VERIFY_FAILED =    -0x0202,
        AMQP_STATUS_SSL_CONNECTION_FAILED =     -0x0203
    } amqp_status_enum;

    typedef enum amqp_response_type_enum_ {
        AMQP_RESPONSE_NONE = 0,
        AMQP_RESPONSE_NORMAL,
        AMQP_RESPONSE_LIBRARY_EXCEPTION,
        AMQP_RESPONSE_SERVER_EXCEPTION
    } amqp_response_type_enum;

    typedef enum amqp_sasl_method_enum_ {
        AMQP_SASL_METHOD_PLAIN = 0
    } amqp_sasl_method_enum;

    typedef int amqp_boolean_t;
    typedef uint16_t amqp_channel_t;
    typedef uint32_t amqp_method_number_t;
    typedef uint32_t amqp_flags_t;

    typedef struct amqp_decimal_t_ {
        uint8_t decimals;
        uint32_t value;
    } amqp_decimal_t;

    typedef struct amqp_array_t_ {
        int num_entries;
        struct amqp_field_value_t_ *entries;
    } amqp_array_t;

    typedef struct amqp_table_t_ {
        int num_entries;
        struct amqp_table_entry_t_ *entries;
    } amqp_table_t;

    typedef struct amqp_field_value_t_ {
        uint8_t kind;
        union {
            amqp_boolean_t boolean;
            int8_t i8;
            uint8_t u8;
            int16_t i16;
            uint16_t u16;
            int32_t i32;
            uint32_t u32;
            int64_t i64;
            uint64_t u64;
            float f32;
            double f64;
            amqp_decimal_t decimal;
            amqp_bytes_t bytes;
            amqp_table_t table;
            amqp_array_t array;
        } value;
    } amqp_field_value_t;

    typedef struct amqp_table_entry_t_ {
        amqp_bytes_t key;
        amqp_field_value_t value;
    } amqp_table_entry_t;

    typedef struct amqp_basic_properties_t_ {
        amqp_flags_t _flags;
        amqp_bytes_t content_type;
        amqp_bytes_t content_encoding;
        amqp_table_t headers;
        uint8_t delivery_mode;
        uint8_t priority;
        amqp_bytes_t correlation_id;
        amqp_bytes_t reply_to;
        amqp_bytes_t expiration;
        amqp_bytes_t message_id;
        uint64_t timestamp;
        amqp_bytes_t type;
        amqp_bytes_t user_id;
        amqp_bytes_t app_id;
        amqp_bytes_t cluster_id;
    } amqp_basic_properties_t;

    typedef struct amqp_method_t_ {
        amqp_method_number_t id;
        void * decoded;
    } amqp_method_t;

    typedef struct amqp_rpc_reply_t_ {
        amqp_response_type_enum reply_type;
        amqp_method_t reply;
        int library_error;
    } amqp_rpc_reply_t;

    typedef struct amqp_pool_blocklist_t_ {
        int num_blocks;
        void **blocklist;
    } amqp_pool_blocklist_t;

    typedef struct amqp_pool_t_ {
        size_t pagesize;
        amqp_pool_blocklist_t pages;
        amqp_pool_blocklist_t large_blocks;
        int next_page;
        char *alloc_block;
        size_t alloc_used;
    } amqp_pool_t;

    typedef struct amqp_message_t_ {
        amqp_basic_properties_t properties;
        amqp_bytes_t body;
        amqp_pool_t pool;
    } amqp_message_t;

    typedef struct amqp_envelope_t_ {
        amqp_channel_t channel;
        amqp_bytes_t consumer_tag;
        uint64_t delivery_tag;
        amqp_boolean_t redelivered;
        amqp_bytes_t exchange;
        amqp_bytes_t routing_key;
        amqp_message_t message;
    } amqp_envelope_t;

    typedef struct amqp_channel_open_ok_t_ {
        amqp_bytes_t channel_id;
    } amqp_channel_open_ok_t;

    typedef struct amqp_basic_consume_ok_t_ {
        amqp_bytes_t consumer_tag;
    } amqp_basic_consume_ok_t;

    typedef struct amqp_queue_declare_ok_t_ {
        amqp_bytes_t queue;
        uint32_t message_count;
        uint32_t consumer_count;
    } amqp_queue_declare_ok_t;

    typedef struct amqp_exchange_declare_ok_t_ {
        char dummy; /* Dummy field to avoid empty struct */
    } amqp_exchange_declare_ok_t;

    typedef struct amqp_queue_bind_ok_t_ {
        char dummy; /* Dummy field to avoid empty struct */
    } amqp_queue_bind_ok_t;

    typedef struct amqp_socket_t_ amqp_socket_t;
    typedef struct amqp_connection_state_t_ *amqp_connection_state_t;

    const amqp_bytes_t amqp_empty_bytes;
    const amqp_table_t amqp_empty_table;
    const amqp_array_t amqp_empty_array;

    uint32_t amqp_version_number();
    char const * amqp_version();
    amqp_bytes_t amqp_bytes_malloc(size_t amount);
    void amqp_bytes_free(amqp_bytes_t bytes);


    amqp_connection_state_t amqp_new_connection();
    amqp_socket_t * amqp_tcp_socket_new(amqp_connection_state_t state);
    int amqp_socket_open(amqp_socket_t *self, const char *host, int port);
    int amqp_tune_connection(amqp_connection_state_t state, int channel_max, int frame_max, int heartbeat);
    int amqp_get_channel_max(amqp_connection_state_t state);
    int amqp_destroy_connection(amqp_connection_state_t state);
    amqp_rpc_reply_t amqp_login(amqp_connection_state_t state, char const * vhost, int channel_max, int frame_max, int heartbeat, amqp_sasl_method_enum sasl_method, ...);
    amqp_rpc_reply_t amqp_get_rpc_reply(amqp_connection_state_t state);
    amqp_queue_declare_ok_t * amqp_queue_declare(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t exclusive, amqp_boolean_t auto_delete, amqp_table_t arguments);
    amqp_exchange_declare_ok_t * amqp_exchange_declare(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t exchange, amqp_bytes_t type, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t auto_delete, amqp_boolean_t internal, amqp_table_t arguments);
    amqp_queue_bind_ok_t * amqp_queue_bind(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_table_t arguments);
    int amqp_basic_publish(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_boolean_t mandatory, amqp_boolean_t immediate, struct amqp_basic_properties_t_ const * properties, amqp_bytes_t body);
    amqp_basic_consume_ok_t * amqp_basic_consume(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t consumer_tag, amqp_boolean_t no_local, amqp_boolean_t no_ack, amqp_boolean_t exclusive, amqp_table_t arguments);
    amqp_channel_open_ok_t * amqp_channel_open(amqp_connection_state_t state, amqp_channel_t channel);
    amqp_rpc_reply_t amqp_channel_close(amqp_connection_state_t state, amqp_channel_t channel, int code);
    amqp_rpc_reply_t amqp_connection_close(amqp_connection_state_t state, int code);
    int amqp_basic_ack(amqp_connection_state_t state, amqp_channel_t channel, uint64_t delivery_tag, amqp_boolean_t multiple);
    amqp_rpc_reply_t amqp_basic_get(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_boolean_t no_ack);
    int amqp_basic_reject(amqp_connection_state_t state, amqp_channel_t channel, uint64_t delivery_tag, amqp_boolean_t requeue);
    int amqp_basic_nack(amqp_connection_state_t state, amqp_channel_t channel, uint64_t delivery_tag, amqp_boolean_t multiple, amqp_boolean_t requeue);
    const char * amqp_error_string2(int err);
    amqp_rpc_reply_t amqp_consume_message(amqp_connection_state_t state, amqp_envelope_t *envelope, struct timeval *timeout, int flags);
    void amqp_destroy_envelope(amqp_envelope_t *envelope);
""")
_C = _ffi.verify("""
#include "amqp.h"
#include "amqp_tcp_socket.h"
""", libraries=["rabbitmq"])

amqp_version_number = _C.amqp_version_number
amqp_version = lambda: _ffi.string(_C.amqp_version())

def _bytes_to_amqp_bytes(b):
    if b is None:
        return _C.amqp_empty_bytes
    amqp_bytes = _C.amqp_bytes_malloc(len(b))
    buf = _ffi.buffer(amqp_bytes.bytes, amqp_bytes.len)
    buf[:] = b
    return amqp_bytes

def _str_to_amqp_bytes(s):
    if s is None:
        return _C.amqp_empty_bytes
    return _bytes_to_amqp_bytes(s.encode("utf-8"))

class Connection(object):
    def __init__(self):
        self._state = _C.amqp_new_connection()

    def open(self, host, port):
        sock = _C.amqp_tcp_socket_new(self._state)
        _C.amqp_socket_open(sock, host.encode("utf-8"), port)

    def get_sockfd(self):
        return _C.amqp_get_sockfd(self._state)

    def tune(self, channel_max, frame_max, heartbeat):
        return _C.amqp_tune_connection(self._state, channel_max, frame_max, heartbeat)

    def open_channel(self, channel):
        return _C.amqp_channel_open(self._state, channel)

    def get_channel_max(self):
        return _C.amqp_get_channel_max(self._state)

    def destroy(self):
        return _C.amqp_destroy_connection(self._state)

    def _check_reply(self, reply):
        if reply.reply_type != _C.AMQP_RESPONSE_NORMAL:
            raise Exception("reply_type=%d, library_error=%d" % (reply.reply_type, reply.library_error))

    def login(self, vhost, sasl_method, *args, **kwargs):
        channel_max = kwargs.pop("channel_max", None)
        frame_max = kwargs.pop("frame_max", None)
        heartbeat = kwargs.pop("heartbeat", None)
        if channel_max is None:
            channel_max = _C.AMQP_DEFAULT_MAX_CHANNELS
        if frame_max is None:
            frame_max = _C.AMQP_DEFAULT_FRAME_SIZE
        if heartbeat is None:
            heartbeat = _C.AMQP_DEFAULT_HEARTBEAT
        args = [_ffi.new("char[]", s.encode("utf-8")) for s in args]
        self._check_reply(_C.amqp_login(self._state, vhost.encode("utf-8"), channel_max, frame_max, heartbeat, sasl_method, *args))

    def declare_queue(self, channel, queue, passive=False, durable=False, exclusive=False, auto_delete=False):
        ok = _C.amqp_queue_declare(self._state, channel, _str_to_amqp_bytes(queue), passive, durable, exclusive, auto_delete, _C.amqp_empty_table)
        reply = _C.amqp_get_rpc_reply(self._state)
        self._check_reply(reply)
        return ok.queue

    def bind_queue(self, channel, queue, exchange, routing_key=None):
        ok = _C.amqp_queue_bind(self._state, channel, _str_to_amqp_bytes(queue), _str_to_amqp_bytes(exchange), _str_to_amqp_bytes(routing_key), _C.amqp_empty_table)
        reply = _C.amqp_get_rpc_reply(self._state)
        self._check_reply(reply)

    def declare_exchange(self, channel, exchange, type, passive=False, durable=False):
        ok = _C.amqp_exchange_declare(self._state, channel, _str_to_amqp_bytes(exchange), _str_to_amqp_bytes(type), passive, durable, _C.amqp_empty_table)
        reply = _C.amqp_get_rpc_reply(self._state)
        self._check_reply(reply)

    def publish(self, channel, exchange, routing_key, body, properties=None, mandatory=False, immediate=False):
        if properties is None:
            properties = _ffi.NULL
        else:
            properties = properties.amqp_properties()
        import logging
        status = _C.amqp_basic_publish(self._state, channel, _str_to_amqp_bytes(exchange), _str_to_amqp_bytes(routing_key), mandatory, immediate, properties, _bytes_to_amqp_bytes(body))
        if status != _C.AMQP_STATUS_OK:
            raise Exception("status=%d" % status)
        reply = _C.amqp_get_rpc_reply(self._state)
        self._check_reply(reply)

    def consume(self, channel, queue, consumer_tag=None, no_local=False, no_ack=False, exclusive=False):
        ok = _C.amqp_basic_consume(self._state, channel, _str_to_amqp_bytes(queue), _str_to_amqp_bytes(consumer_tag), no_local, no_ack, exclusive, _C.amqp_empty_table)
        reply = _C.amqp_get_rpc_reply(self._state)
        self._check_reply(reply)
        return ok.consumer_tag

    def consume_message(self, timeout=None, flags=0):
        envelope = _ffi.new("amqp_envelope_t *")
        if timeout is None:
            timeout = _ffi.NULL
        else:
            # TODO this only works with integer timeouts
            timeout = _ffi.new("struct timeval *")
            timeout.tv_sec = timeout
            timeout.tv_usec = 0
        reply = _C.amqp_consume_message(self._state, envelope, timeout, 0)
        self._check_reply(reply)
        return Envelope(envelope)

    def ack(self, channel, delivery_tag, multiple=False):
        status = _C.amqp_basic_ack(self._state, channel, delivery_tag, multiple)
        if status != _C.AMQP_STATUS_OK:
            raise Exception("status=%d" % status)

    def reject(self, channel, delivery_tag, requeue=False):
        status = _C.amqp_basic_reject(self._state, channel, delivery_tag, requeue)
        if status != _C.AMQP_STATUS_OK:
            raise Exception("status=%d" % status)

def _amqp_bytes(byts):
    return _ffi.buffer(byts.bytes, byts.len)[:]

class Envelope(object):
    def __init__(self, envelope):
        self.channel = envelope.channel
        self.consumer_tag = _amqp_bytes(envelope.consumer_tag).decode("utf-8")
        self.delivery_tag = envelope.delivery_tag
        self.redelivered = envelope.redelivered
        self.exchange = _amqp_bytes(envelope.exchange).decode("utf-8")
        self.routing_key = _amqp_bytes(envelope.routing_key).decode("utf-8")
        self.message = Message(envelope.message)

    def destroy(self):
        _C.amqp_destroy_envelope(self._envelope)

    def __str__(self):
        return "<Envelope: channel={0.channel}, consumer_tag={0.consumer_tag}, delivery_tag={0.delivery_tag}, redelivered={0.redelivered}, exchange={0.exchange}, routing_key={0.routing_key}, message={0.message}>".format(self)

class Properties(object):
    def __init__(self, content_type=None, content_encoding=None, headers=None, delivery_mode=None, priority=None, correlation_id=None,
                       reply_to=None, expiration=None, message_id=None, timestamp=None, type=None, user_id=None, app_id=None, cluster_id=None):
        self.content_type = content_type
        self.content_encoding = content_encoding
        self.headers = headers
        self.delivery_mode = delivery_mode
        self.priority = priority
        self.correlation_id = correlation_id
        self.reply_to = reply_to
        self.expiration = expiration
        self.message_id = message_id
        self.timestamp = timestamp
        self.type = type
        self.user_id = user_id
        self.app_id = app_id
        self.cluster_id = cluster_id

    @classmethod
    def from_amqp_properties(cls, props):
        return cls(content_type=_amqp_bytes(props.content_type).decode("utf-8"),
                   content_encoding=_amqp_bytes(props.content_encoding).decode("utf-8"),
                   headers=props.headers,
                   delivery_mode=props.delivery_mode,
                   priority=props.priority,
                   correlation_id=_amqp_bytes(props.correlation_id).decode("utf-8"),
                   reply_to=_amqp_bytes(props.reply_to).decode("utf-8"),
                   expiration=_amqp_bytes(props.expiration).decode("utf-8"),
                   message_id=_amqp_bytes(props.message_id).decode("utf-8"),
                   timestamp=props.timestamp,
                   type=_amqp_bytes(props.type).decode("utf-8"),
                   user_id=_amqp_bytes(props.user_id).decode("utf-8"),
                   app_id=_amqp_bytes(props.app_id).decode("utf-8"),
                   cluster_id=_amqp_bytes(props.cluster_id).decode("utf-8"))

    def amqp_properties(self):
        props = _ffi.new("amqp_basic_properties_t *")
        flags = 0
        if self.content_type is not None:
            flags = flags | _C.AMQP_BASIC_CONTENT_TYPE_FLAG
            props.content_type = _str_to_amqp_bytes(self.content_type)
        if self.content_encoding is not None:
            flags = flags | _C.AMQP_BASIC_CONTENT_ENCODING_FLAG
            props.content_encoding = _str_to_amqp_bytes(self.content_encoding)
        if self.delivery_mode is not None:
            flags = flags | _C.AMQP_BASIC_DELIVERY_MODE_FLAG
            props.delivery_mode = self.delivery_mode
        if self.correlation_id is not None:
            flags = flags | _C.AMQP_BASIC_CORRELATION_ID_FLAG
            props.correlation_id = _str_to_amqp_bytes(self.correlation_id)
        if self.message_id is not None:
            flags = flags | _C.AMQP_BASIC_MESSAGE_ID_FLAG
            props.message_id = _str_to_amqp_bytes(self.message_id)
        # TODO rest of properties
        props._flags = flags
        return props

    def __str__(self):
        return "<Properties: flags={0.flags}, content_type={0.content_type}, content_encoding={0.content_encoding}>".format(self)

class Message(object):
    def __init__(self, message):
        self.properties = Properties.from_amqp_properties(message.properties)
        self.body = _amqp_bytes(message.body)
        self.pool = message.pool

    def __str__(self):
        return "<Message: properties={0.properties}, body={0.body}, pool={0.pool}>".format(self)

