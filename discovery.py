import socket
import threading
import time
import struct
import rlp
from crypto import keccak256
from secp256k1 import PrivateKey
from ipaddress import ip_address

# The ports are expected to be integers and the address is expected to be in
# the "dot" format "127.0.0.1". The address is passed to the ipaddress library
# so we can use its utility functions.

# The pack method prepares the object to be consumed by rlp.encode, converting it
# to a list of strings. In the EndPoint specification, it demands the
# "BE encoded 4-byte" address, which is exactly what's outputted by
# self.address.packed.

# For the ports, the RLP specification page demands:
# "Ethereum integers must be represented in big endian binary form with no leading
# zeroes", and the Endpoint specification lists their datatypes as uint16_t, or
# unsigned 16-bit integers. So, I use the struck.pack method with the format
# string >H, which means "big-endian unsigned 16-bit integer", according to
# the documentation: https://docs.python.org/2/library/struct.html

class EndPoint(object):
    def __init__(self, address, udpPort, tcpPort):
        self.address = ip_address(address)
        self.udpPort = udpPort
        self.tcpPort = tcpPort

    def pack(self):
        return [self.address.packed,
                struct.pack(">H", self.udpPort),
                struct.pack(">H", self.tcpPort)]

# Instead of converting later, I decided to enter in the raw byte values for
# packet_type and version as constant fields. In the constructor, you need to pass
# in the "from" and "to" endpoints, as listed in the specification. For the pack
# method, we can use the raw value of version, since it's already in bytes. For
# the endpoints, we can use their pack methods, and for the timestamp, since its
# type is listed as uint32_t, or "unsigned 32-bit integer", I'll use struct.pack
# with the format string >I for "big endian unsigned 32-bit integer". I added 60
# to the time stamp to give an extra 60 seconds for this packet to arrive at the
# destination (specification says that packets received with timestamps in the
# past are dropped to prevent replay attacks).

class PingNode(object):
    packet_type = '\x01';
    version = '\x03';
    def __init__(self, endpoint_from, endpoint_to):
        self.endpoint_from = endpoint_from
        self.endpoint_to = endpoint_to

    def pack(self):
        return [self.version,
                self.endpoint_from.pack(),
                self.endpoint_to.pack(),
                struct.pack(">I", time.time() + 60)]


class PingServer(object):
    def __init__(self, my_endpoint):
        self.endpoint = my_endpoint

        ## get private key
        priv_key_file = open('priv_key', 'r')
        priv_key_serialized = priv_key_file.read()
        priv_key_file.close()
        self.priv_key = PrivateKey()
        self.priv_key.deserialize(priv_key_serialized)


    def wrap_packet(self, packet):
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload), raw = True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        payload = sig_serialized[0] + chr(sig_serialized[1]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def udp_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.endpoint.udpPort))

        def receive_ping():
            print "listening..."
            data, addr = sock.recvfrom(1024)
            print "received message[", addr, "]"

        return threading.Thread(target = receive_ping)

    def ping(self, endpoint):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ping = PingNode(self.endpoint, endpoint)
        message = self.wrap_packet(ping)
        print "sending ping."
        sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))
