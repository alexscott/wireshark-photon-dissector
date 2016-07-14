-- Adapted from Cameron Gutman's enet dissector at https://github.com/cgutman/wireshark-enet-dissector licensed to us under GPLv3.

-- TODO: support Photon CRC check
-- TODO: enumerate possible command flags
-- TODO: support encrypted messages
-- TODO: support Photon debug flag
-- TODO: deserialize message parameter table

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

-- Photon message types (things that can be sent in a command)
local message_types = {
   [2] = "Operation request",
   [3] = "Operation response",
   [4] = "Event data",
   [7] = "Operation response"
}

-- Photon operations
local operation_names = {
   [220] = "GetRegions",
   [221] = "GetLobbyStats",
   [222] = "FindFriends",
   [223] = "DebugGame",
   [224] = "CancelJoinRandomGame",
   [225] = "JoinRandomGame",
   [226] = "JoinGame",
   [227] = "CreateGame",
   [228] = "LeaveLobby",
   [229] = "JoinLobby",
   [230] = "Authenticate",
   [248] = "ChangeGroups",
   [249] = "Ping",
   [251] = "GetProperties",
   [252] = "SetProperties",
   [253] = "RaiseEvent",
   [254] = "Leave",
   [255] = "Join"
}

-- Photon events
local event_names = {
   -- Generic Photon events
   [210] = "AzureNodeInfo",
   [224] = "TypedLobbyStats",
   [226] = "AppStats",
   [227] = "Match",
   [228] = "QueueState",
   [229] = "GameListUpdate",
   [230] = "GameList",
   [253] = "PropertiesChanged",
   [254] = "Leave",
   [255] = "Join",

   -- PUN events
   [200] = "RPC",
   [201] = "SendSerialize",
   [202] = "Instantiation",
   [203] = "CloseConnection",
   [204] = "Destroy",
   [205] = "RemoveCachedRPCs",
   [206] = "SendSerializeReliable",
   [207] = "DestroyPlayer",
   [208] = "AssignMaster",
   [209] = "OwnershipRequest",
   [210] = "OwnershipTransfer",
   [211] = "VacantViewIds",

   -- Altspace application-specific events
   [135] = "MulticastRPC",
   [179] = "VoIP"
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

-- unreliable sends
local pf_sendunrel_unrelseqnum = ProtoField.int32("photon.command.sendunrel_unrelseqnum", "Unreliable sequence number", base.DEC)

-- fragment sends
local pf_sendfrag_startseqnum = ProtoField.int32("photon.command.sendfrag_startseqnum", "Start sequence number", base.DEC)
local pf_sendfrag_fragcount = ProtoField.int32("photon.command.sendfrag_fragcount", "Fragment count", base.DEC)
local pf_sendfrag_fragnum = ProtoField.int32("photon.command.sendfrag_fragnum", "Fragment number", base.DEC)
local pf_sendfrag_totallen = ProtoField.int32("photon.command.sendfrag_totallen", "Total length", base.DEC)
local pf_sendfrag_fragoff = ProtoField.int32("photon.command.sendfrag_fragoff", "Fragment offset", base.DEC)
local pf_sendfrag_data = ProtoField.bytes("photon.command.sendfrag_data", "Data")

-- reliable and unreliable sends
local pf_command_msg = ProtoField.bytes("photon.command.message", "Message data")
local pf_command_msg_signifier = ProtoField.uint8("photon.command.message.signifier", "Message signifier byte", base.HEX)
local pf_command_msg_type = ProtoField.uint8("photon.command.message.type", "Message type", base.DEC, message_types)
local pf_command_msg_parametercount = ProtoField.int16("photon.command.message.parametercount", "Parameter count", base.DEC)
local pf_command_msg_parameters = ProtoField.bytes("photon.command.message.parameters", "Parameters", base.HEX)

local pf_command_op_code = ProtoField.uint8("photon.command.message.opcode", "Operation code", base.DEC, operation_names)
local pf_command_op_returncode = ProtoField.uint16("photon.command.message.opreturncode", "Operation return code", base.DEC)
local pf_command_op_debug = ProtoField.uint8("photon.command.operation.opdebug", "Operation debug byte", base.HEX)

local pf_command_ev_code = ProtoField.uint8("photon.command.operation.eventcode", "Event code", base.DEC, event_names)

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
    pf_sendunrel_unrelseqnum,
    pf_sendfrag_startseqnum,
    pf_sendfrag_fragcount,
    pf_sendfrag_fragnum,
    pf_sendfrag_totallen,
    pf_sendfrag_fragoff,
    pf_sendfrag_data,
    pf_command_msg,
    pf_command_msg_signifier,
    pf_command_msg_type,
    pf_command_msg_parameters,
    pf_command_msg_parametercount,
    pf_command_op_code,
    pf_command_op_returncode,
    pf_command_op_debug,
    pf_command_ev_code
}

local command_count_field = Field.new("photon.commandcount")
local command_type_field = Field.new("photon.command.type")
local command_length_field = Field.new("photon.command.length")
local command_msg_type_field = Field.new("photon.command.message.type")

function get_last_field_info(field)
   local tbl = { field() }
   return tbl[#tbl]
end

-- Reads Photon message number `num` from a Photon packet stored in `buf`, starting at `idx` and consuming `len` bytes.
-- Returns the next index after the message is read.
function read_message(buf, idx, num, len, root)
   local tree = root:add(pf_command_msg, len, "Message")
   local msg_header_length = 2
   tree:add(pf_command_msg_signifier, buf(idx, 1))
   tree:add(pf_command_msg_type, buf(idx + 1, 1))

   local msg_type_info = get_last_field_info(command_msg_type_field)
   tree:append_text(string.format(" - %s", msg_type_info.display))

   local msg_type = msg_type_info()
   idx = idx + msg_header_length

   if msg_type == 2 then
      local msg_meta_length = 3
      local data_length = len - msg_header_length - msg_meta_length
      tree:add(pf_command_op_code, buf(idx, 1))
      tree:add(pf_command_msg_parametercount, buf(idx + 1, 2))
      tree:add(pf_command_msg_parameters, buf(idx, data_length))
      return idx + msg_meta_length + data_length
   elseif msg_type == 3 or msg_type == 7 then
      local msg_meta_length = 6
      local data_length = len - msg_header_length - msg_meta_length
      tree:add(pf_command_op_code, buf(idx, 1))
      tree:add(pf_command_op_returncode, buf(idx + 1, 2))
      tree:add(pf_command_op_debug, buf(idx + 3, 1))
      tree:add(pf_command_msg_parametercount, buf(idx + 4, 2))
      tree:add(pf_command_msg_parameters, buf(idx + msg_meta_length, data_length))
      return idx + msg_meta_length + data_length
   elseif msg_type == 4 then
      local msg_meta_length = 3
      local data_length = len - msg_header_length - msg_meta_length
      tree:add(pf_command_ev_code, buf(idx, 1))
      tree:add(pf_command_msg_parametercount, buf(idx + 1, 2))
      tree:add(pf_command_msg_parameters, buf(idx + msg_meta_length, data_length))
      return idx + msg_meta_length + data_length
   end
   return idx
end

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
      return read_message(buf, idx, num, data_length, tree)
   elseif command == 7 then
      local command_meta_length = 4
      tree:add(pf_sendunrel_unrelseqnum, buf(idx, 4))
      local data_length = command_length - command_header_length - command_meta_length
      return read_message(buf, idx + command_meta_length, num, data_length, tree)
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
