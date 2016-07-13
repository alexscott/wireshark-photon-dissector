# wireshark-photon-dissector

A Wireshark dissector for Altspace Photon traffic, derived from the PUN codebase and the ENet dissector [here][enet-dissector]. WIP.

This is almost a general-purpose Wireshark dissector for any Photon traffic. The only Altspace-specific stuff (at this moment) is the enumeration of Altspace ENet channels.

This is *not* almost a general-purpose ENet dissector -- Photon packages up multiple ENet commands into one UDP packet in a Photon-specific (and undocumented?) way, so Photon packets look somewhat different from ENet packets designed to carry only one command.

To run: Execute wireshark with the command-line option "-X lua_script:<path to photon.lua>". Choose a Photon UDP packet to dissect, choose "Decode As..." and select ENet. (You might want to set it as the default decoder for UDP port 5056.)

[enet-dissector]: https://github.com/cgutman/wireshark-enet-dissector
