.. SPDX-License-Identifier: GPL-2.0

==============================================
Ashen Tamper Sensing Heartbeat Protocol Driver
==============================================


cmdline parameters
------------------

Boot-up behavior of the module can be configured either through Kconfig or through the following cmdline overrides:

``ashen-tamper.connect=auto``
    Automatically connect on boot-up with a random, ephemeral identity

``ashen-tamper.heartbeat=auto``
    Start heartbeat timer automatically when connected

Userspace API
-------------

The following paths are provided in the sysfs node of the ashen-tamper instance:

``state``
    State of the connection. One of ``{idle, handshake, connected, error}``.

``remote-identity``
    Public identity key of the remote party. Reads empty when not available.

``local-identity``
    Read: Local public identity key. Write: Set local *private* identity key for next handshake. Writing a valid key
    reocnnects the session with the new key. Write an empty string to erase key.

``armed``
    ``1``: Heartbeat active. ``0``: Heartbeat inactive. Can be read and written.

``locked``
    Connection and heartbeat state locked until next reboot. Can only be written once. ``1``: locked, ``0``: unlocked.

