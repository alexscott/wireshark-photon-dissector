-- Adapted from Cameron Gutman's enet dissector at https://github.com/cgutman/wireshark-enet-dissector licensed to us under GPLv3.

-- TODO: support Photon CRC check
-- TODO: enumerate possible command flags

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

-- Altspace application-specific Photon channels
local channel_names = {
   [1] = "Photon view instantiation",
   [2] = "VoIP",
   [3] = "RPC",
   [4] = "Photon view serialization"
}

local photon = Proto("photon", "Photon")

-- protocol header, present once at the top of every packet
local pf_protoheader_peerid = ProtoField.uint16("photon.peerid", "Peer ID", base.HEX)
local pf_protoheader_crcenabled = ProtoField.uint8("photon.crcenabled", "CRC enabled", base.HEX)
local pf_protoheader_commandcount = ProtoField.uint8("photon.commandcount", "Command count", base.DEC)
local pf_protoheader_timeint = ProtoField.uint32("photon.timeint", "Timestamp", base.DEC)
local pf_protoheader_challenge = ProtoField.int32("photon.challenge", "Challenge", base.DEC)

local pf_command = ProtoField.bytes("Command", "photon.command")

-- command header, present once at the top of each command in the packet
local pf_cmdheader_commandtype = ProtoField.uint8("photon.command.type", "Command type", base.DEC, command_types)
local pf_cmdheader_channelid = ProtoField.uint8("photon.command.channelid", "Channel ID", base.DEC, channel_names)
local pf_cmdheader_commandflags = ProtoField.uint8("photon.command.flags", "Command flags", base.HEX)
local pf_cmdheader_reservedbyte = ProtoField.uint8("photon.command.reservedbyte", "Reserved byte", base.HEX)
local pf_cmdheader_commandlength = ProtoField.int32("photon.command.length", "Command length", base.DEC)
local pf_cmdheader_relseqnum = ProtoField.int32("photon.command.relseqnum", "Reliable sequence number", base.DEC)

-- acknowledgements
local pf_ack_recvrelseqnum = ProtoField.int32("photon.command.ack_recvrelseqnum", "Received reliable sequence number", base.DEC)
local pf_ack_recvsenttime = ProtoField.uint32("photon.command.ack_recvsenttime", "Received sent timestamp", base.DEC)

-- connections
local pf_conn_data = ProtoField.bytes("photon.command.conn_data", "Data", base.HEX)

-- connection verifications
local pf_connverify_data = ProtoField.bytes("photon.command.connverify_data", "Data", base.HEX)

-- reliable sends
local pf_sendrel_data = ProtoField.bytes("photon.command.sendrel_data", "Data")

-- unreliable sends
local pf_sendunrel_unrelseqnum = ProtoField.int32("photon.command.sendunrel_unrelseqnum", "Unreliable sequence number", base.DEC)
local pf_sendunrel_data = ProtoField.bytes("photon.command.sendunrel_data", "Data")

-- fragment sends
local pf_sendfrag_startseqnum = ProtoField.int32("photon.command.sendfrag_startseqnum", "Start sequence number", base.DEC)
local pf_sendfrag_fragcount = ProtoField.int32("photon.command.sendfrag_fragcount", "Fragment count", base.DEC)
local pf_sendfrag_fragnum = ProtoField.int32("photon.command.sendfrag_fragnum", "Fragment number", base.DEC)
local pf_sendfrag_totallen = ProtoField.int32("photon.command.sendfrag_totallen", "Total length", base.DEC)
local pf_sendfrag_fragoff = ProtoField.int32("photon.command.sendfrag_fragoff", "Fragment offset", base.DEC)
local pf_sendfrag_data = ProtoField.bytes("photon.command.sendfrag_data", "Data")

photon.fields = {
    pf_protoheader_peerid,
    pf_protoheader_crcenabled,
    pf_protoheader_commandcount,
    pf_protoheader_timeint,
    pf_protoheader_challenge,
    pf_command,
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
    pf_sendrel_data,
    pf_sendunrel_unrelseqnum,
    pf_sendunrel_data,
    pf_sendfrag_startseqnum,
    pf_sendfrag_fragcount,
    pf_sendfrag_fragnum,
    pf_sendfrag_totallen,
    pf_sendfrag_fragoff,
    pf_sendfrag_data
}

local command_count_field = Field.new("photon.commandcount")
local command_type_field = Field.new("photon.command.type")
local command_length_field = Field.new("photon.command.length")

-- Reads ENet command number `num` from a Photon packet stored in `buf`, starting at `idx`.
-- Returns the next index after the command is read.
function read_command(buf, idx, num, root)

   local command_header_length = 12
   local tree = root:add(pf_command, command_header_length, string.format("Command #%s", num))
   tree:add(pf_cmdheader_commandtype, buf(idx, 1))
   tree:add(pf_cmdheader_channelid, buf(idx + 1, 1))
   tree:add(pf_cmdheader_commandflags, buf(idx + 2, 1))
   tree:add(pf_cmdheader_reservedbyte, buf(idx + 3, 1))
   tree:add(pf_cmdheader_commandlength, buf(idx + 4, 4))
   tree:add(pf_cmdheader_relseqnum, buf(idx + 8, 4))

   local command_type_info = select(num, command_type_field())
   local command_length_info = select(num, command_length_field())

   tree:append_text(string.format(" - %s", command_type_info.display))
   tree:set_len(command_length_info() + command_header_length)

   local command = command_type_info()
   local command_length = command_length_info()
   idx = idx + command_header_length

   if command == 1 then
      local command_meta_length = 8
      tree:add(pf_ack_recvrelseqnum, buf(idx, 4))
      tree:add(pf_ack_recvsenttime, buf(idx + 4, 4))
      return idx + command_meta_length
   elseif command == 2 then
      -- TODO: figure out what these bytes are
      local data_length = command_length - command_header_length
      tree:add(pf_conn_data, buf(idx, data_length))
      return idx + data_length
   elseif command == 3 then
      -- TODO: figure out what these bytes are
      local data_length = command_length - command_header_length
      tree:add(pf_connverify_data, buf(idx, data_length))
      return idx + data_length
   elseif command == 6 then
      local data_length = command_length - command_header_length
      tree:add(pf_sendrel_data, buf(idx, data_length))
      return idx + data_length
   elseif command == 7 then
      local command_meta_length = 4
      tree:add(pf_sendunrel_unrelseqnum, buf(idx, 4))
      local data_length = command_length - command_header_length - command_meta_length
      tree:add(pf_sendunrel_data, buf(idx + command_meta_length, data_length))
      return idx + data_length + command_meta_length
   elseif command == 8 then
      local command_meta_length = 20
      tree:add(pf_sendfrag_startseqnum, buf(idx, 4))
      tree:add(pf_sendfrag_fragcount, buf(idx + 4, 4))
      tree:add(pf_sendfrag_fragnum, buf(idx + 8, 4))
      tree:add(pf_sendfrag_totallen, buf(idx + 12, 4))
      tree:add(pf_sendfrag_fragoff, buf(idx + 16, 4))
      local data_length = command_length - command_header_length - command_meta_length
      tree:add(pf_sendfrag_data, buf(idx + command_meta_length, data_length))
      return idx + data_length + command_meta_length
   else
      return idx
   end
end

function photon.dissector(buf, pkt, root)
    pkt.cols.protocol = "Photon"
    local pktlen = buf:reported_length_remaining()
    local tree = root:add(photon, buf:range(0, pktlen))

    -- read the protocol header
    local proto_header_len = 12
    tree:add(pf_protoheader_peerid, buf(0, 2))
    tree:add(pf_protoheader_crcenabled, buf(2, 1))
    tree:add(pf_protoheader_commandcount, buf(3, 1))
    tree:add(pf_protoheader_timeint, buf(4, 4))
    tree:add(pf_protoheader_challenge, buf(8, 4))

    tree:append_text(string.format(", %s command(s)", command_count_field().display))

    -- read command_count commands
    local idx = proto_header_len
    for num=1,command_count_field()() do
       idx = read_command(buf, idx, num, tree)
    end

    return idx
end

DissectorTable.get("udp.port"):add(5056, photon)
