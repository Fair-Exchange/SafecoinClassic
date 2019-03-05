(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

2018-12-10:   Horizen's TLS incorporated into Safecoin.   Many thanks to the Horzen team for this innovation.   We initially implement this as optional.

UTXO memory accounting
----------------------

The default -dbcache has been changed in this release to 1024MiB. Users can set -dbcache to a higher value (e.g. to keep the UTXO set more fully cached in memory). Users on low-memory systems (such as systems with 2GB or less) should consider specifying a lower value for this parameter.

Additional information relating to running on low-memory systems can be found here: [reducing-memory-usage.md](https://github.com/Fair-Exchange/safecoin/blob/master/doc/reducing-memory-usage.md).