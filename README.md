# secret-aisle

The secret-aisle project is an attempt at creating
a network of servers through which confidential files could be
stored securely and redundantly. See the following goals:

* Be able to upload, split, and distribute data to all 
other machines from any one machine in the network.

* Be able to uniquely recover and recreate data from
any one machine in the network.

* Even if one or several machines stop communicating, still 
be able to recover data with the remaining machines up to 
some level.

* In the event that one or several machines are compromised, 
provide some level of assurance that data will remain 
uncompromised.

* Minimize bandwidth requirements on the network and keep
server & client logic lightweight.

## Implementation Details

Shamir's Secret Sharing Scheme is used to split into 
different shares, each of which is distributed to a machine. A
minimum threshold of shares, specified by the user, is required 
for the data to be fully recovered. Additionally, all data is 
password-protected, such that there are always two layers of 
encryption at work.

All communication between machines is carried out via
pub/sub channels in a centralized Redis server. No
data is actually stored in Redis at any point in time, even
ephemerally.
