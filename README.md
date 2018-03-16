This is an old project to allow a potentially large number of IPv6
hosts to share an entire IPv6 network block.  Yes, this is IPv6 NAT, and
yes, it has some security value, as IPv6 NAT did.  Yes, it does not return
us to the wonderful days of yesteryear when the end-to-end principle
was the pure philosophy of Internet design.

Simply using firewall rules (say, limiting access to outgoing TCP connections)
has security value, but it does leak quite a bit of information about a machine
(its MAC address, for example) and allows simple traffic analysis of
connections.

Aw assigns a separate, random IPv6 address for each outgoing connection
to the Internet by all insiders.   For a large site, this should add
a significant hurdle to monitoring Internet activities of particular users.
for small sites, this should add some anonymity to individual users, along
with the benefits of NAT, such as they are.

This is code written around 2005, and it is untested and unreliable.  I plan
to clean it up and use it on my farm.  I expect to get it working on gateways
running Linux and FreeBSD.

Bill Cheswick
March 2018
