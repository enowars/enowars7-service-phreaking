import socket

# import sctp


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

print("InitUe")
ue_data = ue.recv(1024)
print(ue_data, "\n")
core.sendall(ue_data)

print("AuthReq")
core_data = core.recv(1024)
print(core_data, "\n")
ue.sendall(core_data)

print("AuthRes")
ue_data = ue.recv(1024)
print(ue_data, "\n")
core.sendall(ue_data)

print("SecModeCmd")
core_data = core.recv(1024)
print(core_data, "\n")
ue.sendall(core_data)

print("LocationUpdate")
ue_data = ue.recv(1024)
print(ue_data, "\n")
core.sendall(ue_data)

print("PDUEstReq")
ue_data = ue.recv(1024)
tmp = bytearray(ue_data)
# tmp[-5] = 0x0E
ue_data = bytes(tmp)
print(ue_data, "\n")
core.sendall(ue_data)

print("PDUEstAcc")
core_data = core.recv(1024)
print(core_data, "\n")
ue.sendall(core_data)

print("LocationReportRequest")
ue_data = ue.recv(1024)
print(ue_data, "\n")
core.sendall(ue_data)

print("LocationReportResponse")
core_data = core.recv(1024)
print(core_data, "\n")
ue.sendall(core_data)

core.close()
ue.close()
