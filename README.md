# secret-aisle

The secret-aisle project is an attempt at creating
a network of machines through which confidential files could be
stored securely and redundantly. Every machine on the network
serves dual roles as storage unit and potential client, 
meaning it not only holds files, stores data, and responds
to queries but also it can issue queries of its own to
aggregrate shares from other machines.

In general, the following principles hold:

* If a specific file is compromised, data will remain 
uncompromised up to some user-defined level via usage of a 
secret sharing scheme.
* If an entire machine is compromised, even if shares can 
be readily aggregated by an attacker, data on the network
will still remain encrypted via password protection.
* In the event that one or several machines stop communicating, 
data can be recovered using the remaining machines.
* There is minimal handshaking required to maintain an active 
connection to the network.
* It is easy and cost-efficient to bring a new node into the 
network.
