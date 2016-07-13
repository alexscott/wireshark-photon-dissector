-- Adapted from Cameron Gutman's enet dissector at https://github.com/cgutman/wireshark-enet-dissector licensed to us under GPLv3.

-- TODO: support Photon CRC check
-- TODO: enumerate possible command flags

-- ENetProtocolHeader
local pf_protoheader_peerid = ProtoField.uint16("enet.peerid", "Peer ID", base.HEX)
local pf_protoheader_crcenabled = ProtoField.uint8("enet.crcenabled", "CRC enabled?", base.HEX)
local pf_protoheader_commandcount = ProtoField.uint8("enet.commandcount", "Command count", base.DEC)
local pf_protoheader_timeint = ProtoField.int32("enet.timeint", "Timestamp", base.DEC)
local pf_protoheader_challenge = ProtoField.int32("enet.challenge", "Challenge", base.DEC)

 -- ENet commands 9, 10, and 11 aren't used in Photon AFAIK
local command_types = {
   [1] = "Acknowledge",
   [2] = "Connect",
   [3] = "Verify connect",
   [4] = "Disconnect",
   [5] = "Ping",
   [6] = "Send reliable",
   [7] = "Send unreliable",
   [8] = "Send reliable fragment",
   [9] = "Send unsequenced",
   [10] = "Configure bandwidth limit",
   [11] = "Configure throttling",
   [12] = "Fetch server timestamp"
}

-- https://github.com/AltspaceVR/UnityClient/blob/master/Assets/Altspace/Scripts/Networking/PhotonChannel.cs#L9
local channels = {
   [1] = "Photon view instantiation",
   [2] = "VoIP",
   [3] = "RPC",
   [4] = "Photon view serialization"
}

-- ENetProtocolCommandHeader
local pf_cmdheader_commandtype = ProtoField.uint8("enet.commandtype", "Command type", base.DEC, command_types)
local pf_cmdheader_channelid = ProtoField.uint8("enet.channelid", "Channel ID", base.DEC, channels)
local pf_cmdheader_commandflags = ProtoField.uint8("enet.commandflags", "Command flags", base.HEX)
local pf_cmdheader_reservedbyte = ProtoField.uint8("enet.reservedbyte", "Reserved byte", base.HEX)
local pf_cmdheader_commandlength = ProtoField.int32("enet.commandlength", "Command length", base.DEC)
local pf_cmdheader_relseqnum = ProtoField.int32("enet.relseqnum", "Reliable sequence number", base.DEC)

-- ENetProtocolAcknowledge
local pf_ack_recvrelseqnum = ProtoField.int32("enet.ack.recvrelseqnum", "Received reliable sequence number", base.DEC)
local pf_ack_recvsenttime = ProtoField.int32("enet.ack.recvsenttime", "Received sent timestamp", base.DEC)

-- ENetProtocolConnect
local pf_conn_data = ProtoField.bytes("enet.conn.data", "Data", base.HEX)

-- ENetProtocolVerifyConnect
local pf_connverify_data = ProtoField.bytes("enet.connverify.data", "Data", base.HEX)

-- ENetProtocolBandwidthLimit
local pf_bwlimit_incomingbandwidth = ProtoField.uint32("enet.bwlimit.incomingbandwidth", "Incoming Bandwidth", base.HEX)
local pf_bwlimit_outgoingbandwidth = ProtoField.uint32("enet.bwlimit.outgoingbandwidth", "Outgoing Bandwidth", base.HEX)

-- ENetProtocolThrottleConfigure
local pf_throttle_packetthrottleinterval = ProtoField.uint32("enet.throttle.packetthrottleinterval", "Packet Throttle Interval", base.HEX)
local pf_throttle_packetthrottleaccel = ProtoField.uint32("enet.throttle.packetthrottleaccel", "Packet Throttle Acceleration", base.HEX)
local pf_throttle_packetthrottledecel = ProtoField.uint32("enet.throttle.packetthrottledecel", "Packet Throttle Deceleration", base.HEX)

-- ENetProtocolDisconnect

-- ENetProtocolPing

-- ENetProtocolSendReliable
local pf_sendrel_data = ProtoField.bytes("enet.sendrel.data", "Data")

-- ENetProtocolSendUnreliable
local pf_sendunrel_unrelseqnum = ProtoField.int32("enet.sendunrel.unrelseqnum", "Unreliable sequence number", base.DEC)
local pf_sendunrel_data = ProtoField.bytes("enet.sendunrel.data", "Data")

-- ENetProtocolSendUnsequenced
local pf_sendunseq_unseqgroup = ProtoField.int32("enet.sendunseq.unseqgroup", "Unsequenced Group", base.DEC)
local pf_sendunseq_data = ProtoField.bytes("enet.sendunseq.data", "Data")

-- ENetProtocolSendFragment
local pf_sendfrag_startseqnum = ProtoField.int32("enet.sendfrag.startseqnum", "Start Sequence Number", base.DEC)
local pf_sendfrag_fragcount = ProtoField.int32("enet.sendfrag.fragcount", "Fragment Count", base.DEC)
local pf_sendfrag_fragnum = ProtoField.int32("enet.sendfrag.fragnum", "Fragment Number", base.DEC)
local pf_sendfrag_totallen = ProtoField.int32("enet.sendfrag.totallen", "Total Length", base.DEC)
local pf_sendfrag_fragoff = ProtoField.int32("enet.sendfrag.fragoff", "Fragment Offset", base.DEC)
local pf_sendfrag_data = ProtoField.bytes("enet.sendfrag.data", "Data")

p_enet = Proto ("enet", "ENet")
p_enet.fields = {
    pf_protoheader_peerid,
    pf_protoheader_crcenabled,
    pf_protoheader_commandcount,
    pf_protoheader_timeint,
    pf_protoheader_challenge,
    pf_cmdheader_commandtype,
    pf_cmdheader_channelid,
    pf_cmdheader_commandflags,
    pf_cmdheader_reservedbyte,
    pf_cmdheader_commandlength,
    pf_cmdheader_relseqnum,
    pf_ack_recvrelseqnum,
    pf_ack_recvsenttime,
    pf_conn_data,
    pf_connverify_data,
    pf_bwlimit_incomingbandwidth,
    pf_bwlimit_outgoingbandwidth,
    pf_throttle_packetthrottleinterval,
    pf_throttle_packetthrottleaccel,
    pf_throttle_packetthrottledecel,
    pf_sendrel_data,
    pf_sendunrel_unrelseqnum,
    pf_sendunrel_data,
    pf_sendunseq_unseqgroup,
    pf_sendunseq_data,
    pf_sendfrag_startseqnum,
    pf_sendfrag_fragcount,
    pf_sendfrag_fragnum,
    pf_sendfrag_totallen,
    pf_sendfrag_fragoff,
    pf_sendfrag_data
}

function p_enet.dissector(buf, pkt, root)
    pkt.cols.protocol = p_enet.name

    local proto_tree = root:add(p_enet, buf(0))
    local i = 0

    -- Read the protocol header
    proto_tree:add(pf_protoheader_peerid, buf(i, 2), buf(i, 2):uint())
    i = i + 2
    proto_tree:add(pf_protoheader_crcenabled, buf(i, 1), buf(i, 1):uint())
    i = i + 1

    local command_count = buf(i, 1):uint()
    proto_tree:add(pf_protoheader_commandcount, buf(i, 1), buf(i, 1):uint())
    i = i + 1
    proto_tree:add(pf_protoheader_timeint, buf(i, 4), buf(i, 4):int())
    i = i + 4
    proto_tree:add(pf_protoheader_challenge, buf(i, 4), buf(i, 4):int())
    i = i + 4

    for command_number=1,command_count do

       -- Read the command header
       local command = buf(i, 1):uint()
       local command_name = command_types[command] or "Unknown"
       local command_tree = proto_tree:add(string.format("Command #%s (%s)", command_number, command_name))

       command_tree:add(pf_cmdheader_commandtype, buf(i, 1), buf(i, 1):uint())
       i = i + 1
       command_tree:add(pf_cmdheader_channelid, buf(i, 1), buf(i, 1):uint())
       i = i + 1
       command_tree:add(pf_cmdheader_commandflags, buf(i, 1), buf(i, 1):uint())
       i = i + 1
       command_tree:add(pf_cmdheader_reservedbyte, buf(i, 1), buf(i, 1):uint())
       i = i + 1

       local command_length = buf(i, 4):int()
       command_tree:add(pf_cmdheader_commandlength, buf(i, 4), buf(i, 4):int())
       i = i + 4
       command_tree:add(pf_cmdheader_relseqnum, buf(i, 4), buf(i, 4):int())
       i = i + 4

       local command_headers_length = 12

       if command == 1 then
          -- ENetProtocolAcknowledge
          command_tree:add(pf_ack_recvrelseqnum, buf(i, 4), buf(i, 4):int())
          i = i + 4
          command_tree:add(pf_ack_recvsenttime, buf(i, 4), buf(i, 4):int())
          i = i + 4
       elseif command == 2 then
          -- ENetProtocolConnect
          -- TODO: figure out what these bytes are
          local data_length = command_length - command_headers_length
          command_tree:add(pf_conn_data, buf(i, data_length))
          i = i + data_length
       elseif command == 3 then
          -- ENetProtocolVerifyConnect
          -- TODO: figure out what these bytes are
          local data_length = command_length - command_headers_length
          command_tree:add(pf_connverify_data, buf(i, data_length))
          i = i + data_length
       elseif command == 4 then
          -- ENetProtocolDisconnect
       elseif command == 5 then
          -- ENetProtocolPing
       elseif command == 6 then
          -- ENetProtocolSendReliable
          local data_length = command_length - command_headers_length
          command_tree:add(pf_sendrel_data, buf(i, data_length))
          i = i + data_length
       elseif command == 7 then
          -- ENetProtocolSendUnreliable
          command_tree:add(pf_sendunrel_unrelseqnum, buf(i, 4), buf(i, 4):int())
          i = i + 4
          local data_length = command_length - command_headers_length - 4
          command_tree:add(pf_sendunrel_data, buf(i, data_length))
          i = i + data_length
       elseif command == 8 then
          -- ENetProtocolSendFragment
          command_tree:add(pf_sendfrag_startseqnum, buf(i, 4), buf(i, 4):int())
          i = i + 4
          command_tree:add(pf_sendfrag_fragcount, buf(i, 4), buf(i, 4):int())
          i = i + 4
          command_tree:add(pf_sendfrag_fragnum, buf(i, 4), buf(i, 4):int())
          i = i + 4
          command_tree:add(pf_sendfrag_totallen, buf(i, 4), buf(i, 4):int())
          i = i + 4
          command_tree:add(pf_sendfrag_fragoff, buf(i, 4), buf(i, 4):int())
          i = i + 4
          local data_length = command_length - command_headers_length - 20
          command_tree:add(pf_sendfrag_data, buf(i, data_length))
          i = i + data_length
       elseif command == 9 then
          -- ENetProtocolSendUnsequenced
          command_tree:add(pf_sendunseq_unseqgroup, buf(i, 4), buf(i, 4):int())
          i = i + 4
          local data_length = command_length - command_headers_length - 4
          command_tree:add(pf_sendunseq_data, buf(i, data_length))
          i = i + data_length
       elseif command == 10 then
          -- ENetProtocolBandwidthLimit
          command_tree:add(pf_bwlimit_incomingbandwidth, buf(i, 4), buf(i, 4):uint())
          i = i + 4
          command_tree:add(pf_bwlimit_outgoingbandwidth, buf(i, 4), buf(i, 4):uint())
          i = i + 4
       elseif command == 11 then
          -- ENetProtocolThrottleConfigure
          command_tree:add(pf_throttle_packetthrottleinterval, buf(i, 4), buf(i, 4):uint())
          i = i + 4
          command_tree:add(pf_throttle_packetthrottleaccel, buf(i, 4), buf(i, 4):uint())
          i = i + 4
          command_tree:add(pf_throttle_packetthrottledecel, buf(i, 4), buf(i, 4):uint())
          i = i + 4
       elseif command == 12 then
          -- TODO: ENetProtocolSendUnreliableFragment
       end
    end
end

function p_enet.init()
end

-- FIXME: A better way to get ourselves in the UDP dissector list?
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(0, p_enet)
