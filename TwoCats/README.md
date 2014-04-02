TwoCats and SkinnyCat
=====================

TwoCats is sequential memory and compute time hard password hashing scheme that maximizes
an attackers time*memory cost for guessing passwords.  Christian Forler and Alexander
Peslyak (aka SolarDesigner) provided most of the ideas that I have combined in TwoCats.
While they may not want credit for this work, it belongs to them more than me.

SkinnyCat is a compatible stripped-down version of TwoCats supporting only a memory cost.
It is meant to be simple to implement, yet provide fast memory-hard password security.

Pebble is a tool for estimating decent upper bounds on pebbling difficulty for various DAG
architectures.  It was useful in selecting the sliding-reverse pattern for cache-timing
attack resistance.

Please read TwoCats.odt for a description of the algorithm and credits for ideas.

License
-------

This stuff is free, as in freedom.  I place what I wrote into the public domain.
Bits of twocats-tests.c are borrowed and are under BSD/MIT-like licenses.
