import socket
import sctp

sk = sctp.sctpsocket_tcp(socket.AF_INET)
sk.connect(("127.0.0.1", 3399))

# sk.send(b"\x01")

tcp_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sk.connect(("0.0.0.0", 3000))
tcp_sk.send("START\n".encode())
data = b""
while True:
    tmp = tcp_sk.recv(1)
    data += tmp
    print(tmp)
    if tmp == b"\x99":
        break

print(data)

sk.send(data)

tcp_sk.close()
sk.close()
