import socket
import sctp

sk = sctp.sctpsocket_tcp(socket.AF_INET)
sk.connect(("127.0.0.1", 3399))

sk.send("HALLO".encode())
# while True:
#    print(sk.recv(1).decode())

tcp_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sk.connect(("0.0.0.0", 3000))
tcp_sk.sendall("HI\n".encode())
data = tcp_sk.recv(5)
print(data)

sk.send(data)

tcp_sk.close()
sk.close()
