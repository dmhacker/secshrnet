# secret-aisle

The secret-aisle project is an attempt at creating
a network of machines through which confidential files could be
stored securely and redundantly. Every machine on the network
serves dual roles as storage unit and potential client, 
meaning it not only holds files, stores data, and responds
to queries but also that it can issue queries of its own to
aggregrate shares from other machines.

In general, we try to stay true to the following principles:

* Security
    * If a machine is compromised while offline, data will
    remain uncompromised up to some user-defined level due
    to usage of a secret sharing scheme.
    * If a machine is compromised while online, even if
    shares can be readily aggregated, data on the network
    will still remain encrypted via password protection.
* Fault tolerance
    * In the event that one or several machines stop
    communicating, data can be receovered using the
    remaining machines.
* Low overhead
    * There is minimal handshaking required to maintain
    an active connection to the network.
* Scalability
    * It is easy and cost-efficient to bring a new node
    into the network.
