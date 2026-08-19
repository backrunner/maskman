# MASQUE interoperability record

Every run records the exact Maskman commit, client implementation, TLS
certificate mode, ALPN, HTTP/3 settings, request headers, datagram/capsule
path, payload sizes, expected result, and observed result. The first required
clients are the in-tree Quinn client, an independent MASQUE client, and Pasque
for RFC 9298/9484 reference comparison. `h3-masque` is useful for CONNECT-UDP
coverage but is not treated as a protocol oracle.

No external client result is claimed until a row has been filled with a
reproducible command and packet-level evidence.
