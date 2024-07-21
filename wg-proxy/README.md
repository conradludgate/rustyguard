# wg-proxy

This will be a proxy system for wireguard. Think nginx.

The desire here is that on a VPS I want to expose only 1 port in my firewall.
When I add a new service I don't want to put a new entry in the firewall.
However, I also want the traffic to be encrypted all the way to the application.

The wg-proxy will be the entry point for all WireGuard(R) messages.
By using some clever logic, it will maintain routing tables between receiver IDs and the
backing service.

## Flow

When wg-proxy receives a new handshake initiation message, it will use the mac1
value to determine which peer the message is signed for. The mac1 is defined as

```
mac1_key = hash("mac1----" + receiver_public_key)
mac1 = blake2s_mac(mac1_key, msg)
```

The wg-proxy will know all the receiver public keys that it can route to,
thus it can compute the mac1 according to each public key and find the matching peers.
On a high-end x86_64 CPU, I can complete a single mac1 validation in 250ns. With 20 different
peers configured, we can still easily handle 200krps.

When the application responds with the handshake response message, it will take the `sender`
value out of the packet and store that in a routing table. Should the sender value be already in use,
the handshake packet is slightly dropped. This issue can be circumvented by giving unique sender prefixes to each
application.

When data packets with a matching receiver value are processed, it will use the routing table to determine
which application peer to forward to.

## Cookies and anti DDoS

The wg-proxy will rewrite the mac2 on handshake messages passed through. It must do this as wg-proxy is the only
process that will know the end user IP addresses to validate them.
