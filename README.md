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

A piece of data is identified by a unique tag over the network
with a tag being akin to a file's path on some filesystem. However,
unlike a filesystem, data corresponding to tags are stored in a flat 
non-hierarchical structure; that is, tags sharing the same prefix
are unrelated.

## Setup

TODO

## Architecture

The architecture of the network is fairly simplistic. Within this
network, at any point in time, there are some amount of participating 
host machines, each of which can be grouped into one of two categories:
servers and clients.

### Servers

Servers are the backbone of the network. They listen over the network
for commands from clients and perform one of two actions:
1. If a client sends them a share identified by some tag, they store 
the share locally.
2. If a client requests a tag, they try to find and return a share 
stored locally that matches that tag.

Servers perform little computational work themselves; they primarily
act as trusted storage units that the client can divy out shares to.

### Clients

Clients are the users of the network. They can issue commands to 
servers and send shares to servers on the network for storage. The
client performs all of the cryptographic work needed to protect
their data. When a client wants to send some data over the network,
it will:
1. Encrypt the data using some password.
2. Split the encrypted data into many shares, one for each server.
3. For every online server, send it a unique share and its 
corresponding tag.

Alternatively, a client can reconstruct the data stored at some tag 
by asking every server if it has a share associated with the tag. If
the server has a share, it will send it back to the client.

### Communication

All communication over this network is done over a centralized Redis
server using Redis's pub/sub interface. Every host subscribes to a 
unique channel on Redis, and other hosts that want to send message 
to that host can simply route the packet through the unique channel.
Host discovery is done via channel pattern matching.

### Cryptography

For password protection, passwords are hashed using BLAKE2S to produce
a cryptographic hash. This hash then serves as the secret key for a
ChaCha20-Poly1305 cipher that the plaintext file is fed into.

For secret sharing, a combination of Shamir's Secret Sharing Scheme
and the AES-128 cipher is used. A random 16-byte key is generated and is
then used by AES-128 to encrypt the file. This key is then split using
Shamir's Secret Sharing Scheme into N shares with at least K shares 
required to reconstruct the key. Every server then gets a copy of the
encrypted ciphertext and a share of the key.
