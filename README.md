# secret-sharing-network

The secshrnet project is an attempt at creating a network 
of machines through which confidential files could be stored 
securely and redundantly via application of a secret sharing scheme.
In general, the following principles hold:

* If a specific file is compromised, data will remain 
uncompromised up to some user-defined level via usage of
secret sharing.
* If an entire machine is compromised, even if shares can 
be readily aggregated by an attacker, data on the network
will still remain encrypted via password protection.
* In the event that one or several machines stop communicating, 
data can still be recovered using the remaining machines.
* It is easy and cost-efficient to bring a new node into the 
network.

## Architecture

<p align="center">
  <img width="300" height="300" src="https://raw.githubusercontent.com/dmhacker/secret-sharing-network/master/architecture.png">
</p>

## Setup

TODO
