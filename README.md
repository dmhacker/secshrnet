# secret-aisle

The premise behind the secret-aisle project is simple.
Given a stream of content, uniquely identified by a tag, 
split this data amongst a network of machines in both
a secure and redundant fashion, such that:

* From any online machine connected to the network, be able
to split and distribute the data to all other machines reliably.
* From any online machine connected to the network, be able 
to recover and recreate the data.
* If one or several machines stop communicating, still be
able to recover or recreate the data with the remaining
machines up to some level.
* If one or several machines are compromised when
offline (or even online), provide some level of assurance
that the data will remain uncompromised.

secret-aisle attempts to implement these principles to
keep any data uploaded to the network safe. Data is split
using Shamir's Secret Sharing Scheme into different
shares, each of which is distributed to a machine. A
minimum threshold of shares is required for some data
to be recreated. Additionally, all data is password-protected
and encrypted, such that there are two layers of encryption
always at work.

All communication between machines is carried out via
pub/sub channels in a centralized Redis server. No
data is actually stored in Redis at any point in time.
