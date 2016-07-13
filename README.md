# wireshark-photon-dissector

A Wireshark dissector for Altspace Photon traffic, derived from the PUN codebase and the ENet dissector [here][enet-dissector]. WIP.

This is almost a general-purpose Wireshark dissector for any Photon traffic. The only Altspace-specific stuff (at this moment) is the enumeration of Altspace ENet channels.

This is *not* almost a general-purpose ENet dissector -- Photon packages up multiple ENet commands into one UDP packet in a Photon-specific (and undocumented?) way, so Photon packets look somewhat different from ENet packets designed to carry only one command.

## Usage

Run Wireshark with the command-line option "-X lua_script:<path to photon.lua>" to load the dissector.

UDP packets on port 5056 should be dissected as Photon packets.

[enet-dissector]: https://github.com/cgutman/wireshark-enet-dissector
