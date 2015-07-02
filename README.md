blocknames
==========

Block headers over dns, stuffing all 80 bytes into five IPv6 addresses:

    b1-0.hdr.btc.petertodd.org has IPv6 address 100:0:6fe2:8c0a:b6f1:b372:c1a6:a246
    b1-1.hdr.btc.petertodd.org has IPv6 address ae63:f74f:931e:8365:e15a:89c:68d6:1900
    b1-2.hdr.btc.petertodd.org has IPv6 address ::9820:51fd:1e4b:a744:bbbe:680e
    b1-3.hdr.btc.petertodd.org has IPv6 address 1fee:1467:7ba1:a3c3:540b:f7b1:cdb6:6e8
    b1-4.hdr.btc.petertodd.org has IPv6 address 5723:3e0e:61bc:6649:ffff:1d:1e3:6299

Usage b<height>-<fragment>.hdr.btc.petertodd.org, aside from the minor problem
that it's so slow and buggy most public DNS servers seem to reject it.

Forgive me lord, for I have sinned.


Dependencies
============

Eh, you figure it out. Some ancient version of python-bitcoinrpc, and
python-dnspython.
