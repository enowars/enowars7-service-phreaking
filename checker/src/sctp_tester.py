import socket
import sctp


# sk.send(b"\x01")
"""
core = sctp.sctpsocket_tcp(socket.AF_INET)
core.connect(("127.0.0.1", 3399))
tcp_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sk.connect(("0.0.0.0", 3000))
ue_data = tcp_sk.recv(1024)

print(ue_data)

sk.sendall(ue_data)
core_data = sk.recv(1024)

print(core_data)

tcp_sk.close()
sk.close()

"""

core = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
core.connect(("0.0.0.0", 3399))

ue = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ue.connect(("0.0.0.0", 3000))

# InitUE
ue_data = ue.recv(1024)
print(ue_data, "\n")
core.sendall(ue_data)

# AuthReq
core_data = core.recv(1024)
print(core_data, "\n")
ue.sendall(core_data)

# AuthRes
ue_data = ue.recv(1024)
print(ue_data, "\n")
core.sendall(ue_data)

core.close()
ue.close()
