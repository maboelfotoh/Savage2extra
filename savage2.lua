-- Constants
-- Constants prefixed with SERVER_* are messages that come from the server
SERVER_CHAT = 3
-- This server is graciously....
SERVER_INFO_MSG6 = 6
SERVER_USER_DISCONNECTED_MSG = 25
SERVER_UNKNOWN48 = 48
-- this had the word beast...
SERVER_UNKNOWN54 = 54
SERVER_UNKNOWN62 = 62
SERVER_KILL_NOTIFICATION_MSG = 71
-- Spectators can follow...
SERVER_INFO_MSG = 74
SERVER_UNKNOWN80 = 80

CLIENT_MAGIC = 0xf197de9a

print("Savage 2 LUA dissector DEV")
S2PROTO = Proto("savage2", "Savage 2 Protocol")

-- The dissector function
function S2PROTO.dissector(buffer, pinfo, tree)
  if pinfo.ipproto ~= 17 then
    return
  end

  -- Create the protocol fields
  local f = S2PROTO.fields
  f.seq = ProtoField.uint32("savage2.seq", "Message sequence no.", base.HEX)
  f.magic = ProtoField.uint32("savage2.magic", "Announcement magic no.", base.HEX)
  f.msgid = ProtoField.uint8("savage2.msgid", "Advertisement", base.HEX)
  f.data = ProtoField.stringz("savage2.data", "Data")

  f.chatfield = ProtoField.uint32("savage2.chatfield", "Chat field", base.HEX)

  -- SERVER_KILL_NOTIFICATION specific fields
  f.M71Field1 = ProtoField.uint32("savage2.m71field1", "M71Field1", base.HEX)
  f.M71Field2 = ProtoField.uint32("savage2.m71field2", "M71Field2", base.HEX)
  f.M71Field3 = ProtoField.uint32("savage2.m71field3", "M71Field3", base.HEX)

  -- Client specific fields
  f.clientmagic = ProtoField.uint32("savage2.clientmagic", "Client magic", base.HEX)
  f.CField1 = ProtoField.uint32("savage2.cfield1", "Client field 1", base.HEX)
  f.CField2 = ProtoField.uint32("savage2.cfield2", "Client field 2", base.HEX)
  f.CField3 = ProtoField.uint32("savage2.cfield3", "Client field 3", base.HEX)

  f.SeqNo = ProtoField.uint32("savage2.seqno", "Seq no", base.HEX)
  f.AckNo = ProtoField.uint32("savage2.ackno", "Ack no", base.HEX)
  f.IncNo = ProtoField.uint32("savage2.incno", "Some increasing no", base.HEX)
  f.PlyId = ProtoField.uint32("savage2.plyid", "Player ID", base.HEX)

  -- Fetch data from the packet

  if buffer(0, 4):uint() == 0x9ade97f1 then
    if buffer(8, 13):string() == "S2_K2_CONNECT" then
  --      local version_no = buffer(22):stringz()
        local subtree = tree:add(S2PROTO, buffer())
  --      subtree:add(f.data, buffer(22), "Savage 2 client version: " .. version_no)
        pinfo.cols.protocol = S2PROTO.name
        pinfo.cols.info = "Savage 2 game server connection request"
        return
    elseif buffer(4, 4):uint() == 0x010f8c5b then
        local server_seq_no = buffer(12, 4):le_uint()
        local subtree = tree:add(S2PROTO, buffer())
        subtree:add(f.SeqNo, buffer(12, 4), "Server seq no: " .. server_seq_no)
        return
    elseif buffer(4, 4):uint() == 0x0148a9c7 then
        local subtree = tree:add(S2PROTO, buffer())
        pinfo.cols.info = "Savage 2 undecoded packet"
        return
    elseif buffer(4, 4):uint() == 0x010f8c60 then
        if buffer(8, 1):uint() == 6 then
          --player has connected message
          local msg = buffer(9):stringz()
          local subtree = tree:add(S2PROTO, buffer())
          subtree:add(f.data, buffer(9), "Message: " .. msg)
          pinfo.cols.protocol = S2PROTO.name
          return
        end
    elseif buffer(4, 4):uint() == 0x0548a9 then
        pinfo.cols.info = "Savage 2 undecoded packet"
        return
    elseif buffer(4, 1):uint() == 5 then
        local ack_no = buffer(7, 4):le_uint()
        local subtree = tree:add(S2PROTO, buffer())
        subtree:add(f.AckNo, buffer(7, 4), "Client ack no: " .. ack_no)
        return
--    elseif buffer(4, 1):uint() == 1 then
--        local seq_no = buffer(8, 4):le_uint()
--        local inc_no = buffer(12, 4):le_uint()
--        local subtree = tree:add(S2PROTO, buffer())
--        subtree:add(f.SeqNo, buffer(8, 4), "Client seq no: " .. seq_no)
--        subtree:add(f.IncNo, buffer(12, 4), "Some increasing no: " .. inc_no)
--        return
    end
  end

  if buffer(0, 4):le_uint() == 1 then
    if buffer(4, 1):uint() == 3 and buffer(8, 4):le_uint() == 0x85 then
    --connection request to game server (net_cookie, net_maxBPS, net_name, etc.)
    --{name,val} pairs start from byte 12, separator is ff and list terminated with c2
    tree:add(S2PROTO, buffer())
    pinfo.cols.protocol = S2PROTO.name
    pinfo.cols.info = "Savage 2 client attributes"
    return
    end
  end

  if buffer(4, 1):uint() == 0x03 and buffer(7, 1):uint() == 0x60 then
    if buffer(8, 1):uint() == 3 then
      -- AllChat incoming
      local player_id = buffer(9, 4):le_uint()
      local message = buffer(13):stringz()
      local subtree = tree:add(S2PROTO, buffer())
      subtree:add(f.PlyId, buffer(9, 4), "Player ID: " .. player_id)
      subtree:add(f.data, buffer(13), "AllChat Message: " .. message)
      pinfo.cols.protocol = S2PROTO.name
      pinfo.cols.info = "AllChat incoming message"
      return
    elseif buffer(8, 1):uint() == 4 then
      -- TeamChat incoming
      local player_id = buffer(9, 4):le_uint()
      local message = buffer(13):stringz()
      local subtree = tree:add(S2PROTO, buffer())
      subtree:add(f.PlyId, buffer(9, 4), "Player ID: " .. player_id)
      subtree:add(f.data, buffer(13), "TeamChat Message: " .. message)
      pinfo.cols.protocol = S2PROTO.name
      pinfo.cols.info = "TeamChat incoming message"
      return
    elseif buffer(8, 1):uint() == 5 then
      -- SquadChat incoming
      local player_id = buffer(9, 4):le_uint()
      local message = buffer(13):stringz()
      local subtree = tree:add(S2PROTO, buffer())
      subtree:add(f.PlyId, buffer(9, 4), "Player ID: " .. player_id)
      subtree:add(f.data, buffer(13), "SquadChat Message: " .. message)
      pinfo.cols.protocol = S2PROTO.name
      pinfo.cols.info = "SquadChat incoming message"
      return
    elseif buffer(8, 1):uint() == 0x47 then
      -- Player kill incoming notification message
      local field1 = buffer(9,4):le_uint()
      local field2 = buffer(13,4):le_uint()
      local field3 = buffer(17,4):le_uint()
      local data71 = buffer(21):stringz()
      subtree:add(f.M71Field1, buffer(9,4), "Field 1: " .. field1)
      subtree:add(f.M71Field2, buffer(13,4), "Field 2: " .. field2)
      subtree:add(f.M71Field3, buffer(17,4), "Field 3: " .. field3)
      subtree:add(f.data, buffer(21), "Message: " .. data71)
      pinfo.cols.info = "Kill notification"
      return
    end
  end

  local offset = 0
  local seq_range = buffer(offset, 4)
  local seq = seq_range:le_uint()
  offset = offset + 4
  local magic = buffer(offset, 4):le_uint()


  if buffer(4, 4):uint() == 0x0325d360 then
    offset = offset + 4
    local msgid = buffer(offset, 1):uint()
    offset = offset + 1
    local data = buffer(offset):stringz()
  
    -- Adding fields to the tree
    local subtree = tree:add(S2PROTO, buffer())
    subtree:append_text(", Seq no: " .. seq)
    subtree:append_text(", Announcement magic no: " .. magic)
    subtree:add_le(f.seq, buffer(0, 4), "Sequence no: " .. seq)
    subtree:add_le(f.magic, buffer(4, 4), "Magic no: " .. magic)
    subtree:add(f.msgid, buffer(8, 1), "Msg ID: " .. msgid)

    --do case switching for message type here
    if msgid == SERVER_CHAT then
      local chatfield = buffer(9,4):le_uint()
      subtree:add(f.chatfield, buffer(9,4), "Chat field: " .. chatfield)
      subtree:add(f.data, buffer(13), "Message: " .. buffer(13):stringz())
    elseif msgid == SERVER_INFO_MSG6 then
      subtree:add(f.data, buffer(9), "Message: " .. data)
    elseif msgid == SERVER_KILL_NOTIFICATION_MSG then
    elseif msgid == 25 then
      --player disconnection notification
      pinfo.cols.info = "Player disconnection notification"
    else
      subtree:add(f.data, buffer(9), "Message: " .. data)    
    end  

    -- Modify columns
    pinfo.cols.protocol = S2PROTO.name
    --pinfo.cols.info:append(data)
 -- else
 --   tree:add(S2PROTO, buffer())
  end
end


--register_postdissector(S2PROTO)

-- Register the dissector
udp_table = DissectorTable.get("udp.port")
udp_table:add(17842, S2PROTO)
udp_table:add(17540, S2PROTO)
udp_table:add(11239, S2PROTO)
udp_table:add(11238, S2PROTO)

-- An initialization routine
local packet_counter

function S2PROTO.init()
  packet_counter = 0

  -- Add an integer preference
  --local p = S2PROTO.prefs
  --p.value = Pref.uint("Value", 0, "Start value for counting")

  -- Use the preference
  --if not pinfo.visited and msgid:uint() >= p.value then
  --  packet_counter = packet_counter + 1
  --end
end
