# A Haskell wrapper around the C libpcap library.

It provides Haskell bindings for most of the libpcap API as of libpcap
version 0.9.7.  The bindings are divided into a very efficient
low-level wrapper, Network.Pcap.Base, and a higher-level module,
Network.Pcap, that's easier to use.

To install:

    cabal install pcap


# Get involved!

Please report bugs via the
[github issue tracker](https://github.org/bos/pcap).

There's also a [git mirror](http://github.com/bos/pcap):

* `git clone git://github.com/bos/pcap.git`

Master [Mercurial repository](http://bitbucket.org/bos/pcap):

* `hg clone http://bitbucket.org/bos/pcap`

(You can create and contribute changes using either Mercurial or git.)


# Authors

This library was originally written by Gregory Wright, with contributions
by Dominic Steinitz.  The current maintainer is Bryan O'Sullivan,
<bos@serpentine.com>.
