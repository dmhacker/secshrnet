# secret-sharing-network

This project is an attempt at creating a network 
of machines through which confidential files could be stored 
securely and redundantly via usage of several security mechanisms,
namely secret sharing, key derivation, and file encryption.

Any piece of data stored on the network is identified by a user-defined,
unique tag; this tag is analogous to an absolute path on a filesystem. 
However, unlike a filesystem, data corresponding to tags are stored in 
a flat non-hierarchical structure; that is, tags sharing the same prefix
are unrelated.

## Setup

Install using `pip` via:

```
pip install secshrnet
```

To run a server, use:

```
secshrnetd -c <CONFIG_FILE> -r <ROOT_DIRECTORY>
```

The root directory specifies where the secshrnet daemon will
keep its share files along with other metadata. This defaults 
to **$HOME/.secshrnet**.

The configuration file specifies which Redis instance to connect
to. Please see [example.conf](https://github.com/dmhacker/secret-sharing-network/blob/master/example.conf) for an example configuration.
If a configuration file isn't explicitly provided, `secshrnetd`
will assume the configuration file can be found at
**secshrnet.conf** in the root directory.

To run a client, use:

```
secshrnetc -c <CONFIG_FILE>
```

This will open up a prompt through which commands can be relayed.
Use `help` to see available commands. Again, the configuration
file will be assumed to be at **$HOME/.secshrnet/secshrnet.conf**
if not explicitly passed in.

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

File encryption is implemented via a combination of the scrypt key 
derivation function and the ChaCha20-Poly1305 cipher.

Secret sharing is implementing via a combination of Shamir's 
Secret Sharing Scheme and the AES-128 cipher. Every participating
server gets a copy of the encrypted ciphertext and a share of a 
randomly-generated secret key. The secret key is only reproducible
if enough servers are willing to collaborate in the network.
