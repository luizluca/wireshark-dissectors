iodine = Proto("IODINE",  "IODINE tunnel through DNS server")
dns_qry_name_f = Field.new("dns.qry.name")
dns_txt_f = Field.new("dns.txt")
dns_data_f = Field.new("dns.data")
dns_flags_response_f = Field.new("dns.flags.response")

domain_F = ProtoField.string("iodine.domain","Domain")
type_F = ProtoField.string("iodine.type","Type")
version_F = ProtoField.uint32("iodine.version","Version", base.HEX)
enc_F = ProtoField.string("iodine.enc","Encoding")
encpayload_F = ProtoField.bytes("iodine.payload","Encoded Payload")
result_F = ProtoField.string("iodine.result","Result")
login_challenge_F = ProtoField.uint32("iodine.login_challenge","Login Challenge", base.HEX)
login_hash_F = ProtoField.bytes("iodine.login_hash","Login Hash (XORed Login Challanged)")
maxusers_F = ProtoField.uint32("iodine.maxusers","Max Users", base.DEC)
userid_F = ProtoField.uint32("iodine.user_id","User ID", base.DEC)
cmc_F = ProtoField.uint16("iodine.CMC","Cache Miss Counter", base.HEX)

server_ipv4_F = ProtoField.ipv4("iodine.server_address", "Server Address")
client_ipv4_F = ProtoField.ipv4("iodine.client_address", "Client Address")
mtu_F = ProtoField.uint16("iodine.mtu","MTU", base.DEC)
netmask_F = ProtoField.uint8("iodine.netmask","Netmask", base.DEC)

server_ext_ipv4_F = ProtoField.ipv4("iodine.server_external_address", "Server External Address")
server_ext_ipv6_F = ProtoField.ipv6("iodine.server_external_address", "Server External Address")

fragsize_F = ProtoField.uint16("iodine.frag_size","Fragment Size", base.DEC)

iodine.fields = { domain_F, type_F, version_F, enc_F, encpayload_F, result_F, login_challenge_F, maxusers_F, userid_F, login_hash_F, server_ipv4_F, client_ipv4_F, mtu_F, netmask_F, cmc_F, server_ext_ipv4_F, server_ext_ipv6_F, fragsize_F }

local known_domains = {}
local fragments = {}

local ethertype_table = DissectorTable.get("ethertype")

--local bit32 = require("bit32") -- Biblioteca para operações bitwise
local bit32 = bit
local base32_chars  = "abcdefghijklmnopqrstuvwxyz012345" -- 5 bits per char
local base64_chars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+" -- 6 bits per char
local base64u_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" -- 6 bits per char
local additional_chars = {}
for c = 188, 191 do table.insert(additional_chars, string.char(c)) end
for c = 192, 253 do table.insert(additional_chars, string.char(c)) end
local base128_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"..table.concat(additional_chars)

-- gets a bytearray and a table of chars and returns a bytearray with the data decoded.
-- if required_bits is provided, it will return partial results, aligning to the lowest
-- significant bit (network order).
local function baseN_decode(input, baseN_chars, required_bits, ignorecase)
	local output = {}
	local bits = 0
	local buffer = 0

	local bits_per_char = math.log(#baseN_chars,2)
	if not (bits_per_char % 1) == 0 then
		error("baseN_chars size is not a power of 2")
	end

	for i = 0, input:len()-1 do
		local char = input:raw(i, 1)
		-- break on padding
		if char == "=" then
			break
		end
		if ignorecase then
			-- not expected, but avoids error if the capture is lower during the path
			char = char:lower()
		end
		local val = baseN_chars:find(char)
		if not val then error("Invalid char "..char.."("..char:byte()..") in string "..input():bytes():tohex(true,":")) end
		val = val - 1 -- lua index is 1-based, we need 0-based

		-- make room for the next bits and save them
		buffer = bit32.lshift(buffer, bits_per_char) + val
		bits = bits + bits_per_char

		-- when we have more than 8 bits, we can build a byte
		while bits >= 8 do
			-- get the more significant 8 bits
			bits = bits - 8
			local byte = bit32.rshift(buffer, bits) % 256
			table.insert(output, string.char(byte))
			-- and subtract from the buffer to avoid overflow
			buffer = buffer - bit32.lshift(byte, bits)
		end
	end

	--  if a specific number of bits were requested
	if required_bits then
		local extra_bits = required_bits - 8*#output
		if extra_bits == 0 then
			-- we have enough bits
		elseif extra_bits < 0 then
			-- we have too much bits
			error("Data provided "..(8*#output).." bits, more than the specifically required "..required_bits)
		elseif bits >= extra_bits then
			-- we need to include the extra bits to satisfy the required bits
			-- right-shift everything to align with the less significant bit
			local byte = 0
			for i = 1,#output do
				local old_byte = output[i]:byte()
				output[i] = string.char(bit32.rshift(old_byte,8-extra_bits) + byte)
				byte = bit32.lshift(old_byte,extra_bits) % 256
			end
			-- get the extra bits (and discard what is not needed)
			byte = byte + bit32.rshift(buffer, bits - extra_bits)
			-- useless but ...
			bits = bits - extra_bits
			table.insert(output, string.char(byte))
		else
			error("Data provided "..(8*#output+bits).." bits but the call specifically required " .. required_bits)
		end
	end

	return ByteArray.new(table.concat(output),true)
end

local function dis_base32(buffer, tree, bits, bytearray)
	local item
	if bytearray then
		item = tree:add(encpayload_F, buffer(), bytearray:raw())
	else
		item = tree:add(encpayload_F, buffer())
	end

	local bytes = baseN_decode(bytearray or buffer(), base32_chars, bits, true)
       	local tvb = ByteArray.tvb(bytes, "Decoded base32")
	return tvb, item
end

local function dis_base64(buffer, tree, bits, bytearray)
	local item = tree:add(encpayload_F, buffer())
	local bytes = baseN_decode(bytearray or buffer(), base64_chars, bits)
       	local tvb = ByteArray.tvb(bytes, "Decoded base64")
	return tvb, item
end

local function dis_base128(buffer, tree, bits, bytearray)
	local item = tree:add(encpayload_F, buffer())
	local bytes = baseN_decode(bytearray or buffer(), base128_chars, bits)
       	local tvb = ByteArray.tvb(bytes, "Decoded base128")
	return tvb, item
end

local function dis_hex(buffer, tree, bits, bytearray)
	local item = tree:add(encpayload_F, buffer())
	local bytes
	if buffer():len() == 1 then
		bytes = ByteArray.new("0"..buffer():raw())
	else
		bytes = ByteArray.new(buffer():raw())
	end
	local tvb = ByteArray.tvb(bytes, "Decoded Hex")
	return tvb, item
end

local dict32_chars  = "abcdefghijklmnopqrstuvwxyz0123456789"
local function dis_dict36(buffer, tree, bits, bytearray)
	local item = tree:add(encpayload_F, buffer())
	local bytes
	if not buffer():len() == 1 then
		error("To be used on single byte")
	end
	local char = buffer(0,1):raw()
	local val = dict32_chars:find(char)
	if not val then error("Invalid char "..char.."("..char:byte()..")") end
	val = val - 1 -- lua index is 1-based, we need 0-based
	bytes = ByteArray.new(string.format("%02x",val))

	local tvb = ByteArray.tvb(bytes, "Decoded Dict32")
	return tvb, item
end

BASE32 = "base32"
BASE64 = "base64"
BASE128 = "base128"
RAW = "raw"
codecs = { t=BASE32, s=BASE64, u="base64u", v=BASE128, r=RAW }
codecs_bits = { [5]=BASE32, [6]=BASE64, [26]="base64u", [7]=BASE128, [-1]=RAW }

local function dis_data(buffer, tree, bits, bytearray)
	local codec = codecs[string.lower(buffer(0,1):string())]
	if not codec then
		error("'"..string.lower(buffer(0,1):string()).."' is not a known codec prefix")
		return false
	end

	tree:add(enc_F,buffer(0,1),codec)
	if codec == BASE32 then
		return dis_base32(buffer(1), tree, bits, bytearray)
	elseif codec == BASE64 then
		-- broken?
		return dis_base64(buffer(1), tree, bits, bytearray)
	elseif codec == BASE128 then
		-- broken?
		return dis_base128(buffer(1), tree, bits, bytearray)
	elseif codec == RAW then
		return buffer(1), tree
	else
		error('Coded '..codec..' still not implemented')
	end

	return false
end

local function dis_version_request(buffer, tree)
	if not buffer:len() == 6 then
		return false
	end
	--	4 bytes big endian protocol version
	tree:add(version_F,buffer(0,4))
	--	2 byte Cache Miss Counter, increased every time it is used
	tree:add(cmc_F,buffer(4,2))
	return true
end

local function dis_version_answer(buffer, tree)
	if not buffer:len() == 9 then
		return false
	end
	--	4 chars:
	--		VACK (version ok), followed by login challenge
	--		VNAK (version differs), followed by server protocol version
	--		VFUL (server has no free slots), followed by max users
	tree:add(result_F,buffer(0,4))
	local res = buffer(0,4):string()
	local var
	if res == "VACK" then
		var = login_challenge_F
	elseif res == "VNAK" then
		var = version_F
	elseif res == "VFUL" then
		var = maxusers_F
	else
		return false
	end
	--	4 byte value: means login challenge/server protocol version/max users
	tree:add(var,buffer(4,4))
	if res == "VACK" then
	--	1 byte userid of the new user, or any byte if not VACK
		tree:add(userid_F,buffer(8,1))
	end
	return true
end

local function dis_login_request(buffer, tree)
	if not buffer:len() == 19 then
		return false
	end
	-- 	1 byte userid
	tree:add(userid_F,buffer(0,1))
	-- 	16 bytes MD5 hash of: (first 32 bytes of password) xor (8 repetitions of login challenge)
	tree:add(login_hash_F,buffer(1,16))
	--	2 byte Cache Miss Counter, increased every time it is used
	tree:add(cmc_F,buffer(17,2))
	return true
end

local function dis_login_answer(buffer, tree)
	-- FIXME: test bad login size
	if not buffer:len() == 19 then
		return false
	end

	local res = buffer(0,4):string()
	if res == "LNAK" then
		tree:add(result_F,buffer(0,4))
	else
		res = buffer():string()
		tree:add(result_F,"SUCC")

		local match
		local server_ipv4, client_ipv4, mtu, netmask = string.match(res, "^(.-)%-([^%-]+)%-([^%-]+)%-([^%-]+)$")
		tree:add(server_ipv4_F, buffer(0,#server_ipv4), Address.ip(server_ipv4))
		tree:add(client_ipv4_F, buffer(#server_ipv4+1,#client_ipv4), Address.ip(client_ipv4))
		tree:add(mtu_F, buffer(#server_ipv4+#client_ipv4+2,#mtu), mtu)
		tree:add(netmask_F, buffer(#server_ipv4+#client_ipv4+#mtu+3,#netmask), netmask)
	end
	return true
end

local function dis_ip_request1(buffer, tree)
	if not buffer:len() == 1 then
		return false
	end

	-- 	5-bit userid
	tree:add(userid_F,buffer(0,1))
	local user_id = buffer(0,1):uint()
	return true, user_id
end
local function dis_ip_request2(buffer, tree)
	if not buffer:len() == 2 then
		return false
	end
	tree:add(cmc_F,buffer(0,2))
	return true
end

local function dis_ip_answer(buffer, tree)
	if not (buffer:len() == 5 or buffer:len() == 17) then
		return false
	end

	local res = buffer(0,1):string()
	if not res == "I" then
		res = buffer(0,5):string()
		if res == "BADIP" then
	-- 	BADIP if bad userid
			tree:add(result_F,buffer(0,5))
			return true
		end

		-- unknown answer... it should be BADIP or I
		return false
	end
	-- 	First byte I
	-- 	Then comes external IP address of iodined server
	-- 	as 4 bytes (IPv4) or 16 bytes (IPv6)
	tree:add(result_F,"SUCC")

	if (buffer:len() == 5) then
		tree:add(server_ext_ipv4_F, buffer(1))
	else
		tree:add(server_ext_ipv6_F, buffer(1))
	end
	return true
end

local function dis_upcodec_check_request(buffer, tree)
	tree:add(buffer(),"Payload")
	return true
end

local function dis_upcodec_check_answer(buffer, tree, query_tvb)
	tree:add(query_tvb(),"Expected Payload")
	payload_tree = tree:add(buffer(),"Payload")

        if buffer() ~= query_tvb() then
		payload_tree:add_expert_info(
		  PI_MALFORMED,
		  PI_WARN,
		  "Expected answer did not match"
		)
	end
	return true
end

local function dis_downcodec_check_request1(buffer, tree)
	if not buffer:len() == 1 then
		return false
	end

	local codec = codecs[string.lower(buffer(0,1):string())]
	if not codec then
		subtree.hidden = true
		return
	end

	tree:add(enc_F,buffer(0,1),codec)
	return true
end
local function dis_downcodec_check_request2(buffer, tree)

	if not buffer:len() == 1 then
		return false
	end

	-- FIXME: add the single check variant description
	tree:add(buffer(0,1),"Check Variant:",1)
	return true
end


local DOWNCODEC_CHECK_PAYLOAD = ByteArray.new("00000000ffffffff55555555aaaaaaaa8163c8d2c77cb2175f4fcec9492d522161a9712025b30673e6d84430795057bf")
local function dis_downcodec_check_answer(buffer, tree)
	if not buffer:len() == 2 then
		return false
	end
	if buffer:bytes() == DOWNCODEC_CHECK_PAYLOAD then
		tree:add(buffer(),"Payload (OK)")
	else
		tree:add(buffer(),"Payload (BAD)")
	end
	return true
end

local function dis_switch_codec_request2(buffer, tree)
	if not buffer:len() == 1 then
		return false
	end

	local codec = codecs_bits[buffer():uint()]
	if not codec then
		error("Unknown codec number "..buffer():uint())
	end

	tree:add(enc_F,buffer(0,1),codec)
	return true
end

local function dis_probe_fragsize_request1(buffer, tree)
	if not buffer:len() == 2 then
		return false
	end

	--15 bits coded as 3 Base32 chars: UUUUF FFFFF FFFFF
	-- meaning 4 bits userid, 11 bits fragment size
	tree:add(userid_F,   buffer(0,1), bit32.rshift(bit32.band(buffer(0,2):uint(), 0x7800), 11))
	tree:add(fragsize_F, buffer(0,2), bit32.band(buffer(0,2):uint(), 0x7ff))

	return true
end

local function dis_probe_fragsize_answer(buffer, tree)
	-- The first two bytes contain the requested length.
	tree:add(fragsize_F, buffer(0,2))
	-- The third byte is 107 (0x6B).
	if buffer(2,1):uint() == 0x6b then
		tree:add(buffer(2,1),"Fixed value (OK):", buffer(2,1):uint())
	else
		tree:add(buffer(2,1),"Fixed value (BAD):", buffer(2,1):uint())
	end
	-- The fourth byte is a random value
	tree:add(buffer(3,1),"Random value:", buffer(3,1):uint())
	--, and each following byte is incremented with 107.
	-- This is checked by the client to determine corruption.
	local sum=buffer(3,1):uint()
	local check="OK"
	for i = 4,buffer:len()-1 do
		sum = (sum+0x6b)%256
		if not sum == buffer(i,1):uint() then
			check="BAD"
			break
		end
	end
	tree:add(buffer(4),"Payload (" .. (check) .."):", buffer(3,1):uint())

	return true
end

LAZY="lazy"
IMMEDIATE="Immediate"
local modes = {l=LAZY, i=IMMEDIATE}
local function dis_options_request2(buffer, tree)
	if not buffer:len() == 1 then
		return false
	end

	local codec = codecs[buffer:raw(0,1)]
	if not codec then
		local mode = modes[buffer:raw(0,1)]

		if not mode then
			error("Unknown codec or mode char "..buffer():uint())
		end
		--tree:add(mode_F,buffer(0,1),mode)
		tree:add(buffer(0,1),"Mode: ", mode)
	else
		tree:add(enc_F,buffer(0,1),codec)
	end
	return true
end

local function dis_options_answer(buffer, tree)
	tree:add(result_F,buffer())
	return true
end

local function dis_down_fragsize_request(buffer, tree)
	if not buffer:len() == 3 then
		return false
	end

	-- 1 byte userid
	tree:add(userid_F,buffer(0,1))
	-- 2 bytes new downstream fragment size
	tree:add(fragsize_F, buffer(1,2) ,buffer(1,2):uint())

	return true
end

local function dis_down_fragsize_answer(buffer, tree)
	-- BADFRAG if not accepted
	if buffer():raw() == "BADFRAG" then
		local item = tree:add(result_F,buffer())
		item:add_expert_info(PI_ERROR)
		return true
	end

	-- FIXME: add a property
	-- 2 bytes new downstream fragment size.
	tree:add(buffer(),"Fragment Size:",buffer():uint())
	return true
end

local function dis_ping_request(buffer, tree)
	if not buffer:len() == 4 then
		return false
	end

	-- 1 byte userid
	tree:add(userid_F,buffer(0,1))
	-- 2 bytes new downstream fragment size
	-- FIXME: add a property
	tree:add(buffer(1,1), "SEQUENCE:",buffer(1,2):uint())

	tree:add(cmc_F,buffer(2,2))
	return true
end

local function dis_ping_answer(buffer, tree)
	-- FIXME: add a property
	-- 2 bytes new downstream fragment size.
	tree:add(buffer(),"???:",buffer(0,2):bytes():tohex())
	if buffer:len() > 2 then
		tree:add(buffer(),"Downstream data package:",buffer(2):bytes():tohex())
	end
	return true
end

local function dis_data_request2(buffer, tree, pinfo, domain_name, user_id)
	if not buffer:len() == 3 then
		return false
	end
        --  .... 654 32 10 765 4321 0 .....
	--  3210 432 10 43 210 4321 0 43210
	-- +----+---+--+--+---+----+-+-----+
	-- |UUUU|SSS|FF|FF|DDD|GGGG|L|UDCMC|
	-- +----+---+--+--+---+----+-+-----+
	-- L = Last fragment in packet flag
	-- SSS = Upstream packet sequence number
	-- FFFF = Upstream fragment number
	-- DDD = Downstream packet sequence number
	-- GGGG = Downstream fragment number

	-- UUUU is user id previously processed
	-- UDCMC will be processed after this method

	-- FIXME: add properties

	local up_packet_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x7000),12)
	local up_frag_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x0f00),8)
	local down_packet_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x00e0),5)
	local down_frag_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x001E),1)
	local is_last_frag = bit32.rshift(bit32.band(buffer(0,2):uint(),0x0001),0)==1
	tree:add(buffer(0,1), "Upstream packet sequence number:",up_packet_num)
	tree:add(buffer(0,1), "Upstream fragment number:",up_frag_num)
	tree:add(buffer(1,1), "Downstream packet sequence number:",down_packet_num)
	tree:add(buffer(1,1), "Downstream fragment number:",down_frag_num)
	tree:add(buffer(1,1), "Last fragment in packet:",is_last_frag)
	
	-- FIXME: when fragments do not increase, it might be just an ack 
	pinfo.cols.info:set("Fragmented packet User:"..tostring(user_id).."->"..domain_name.." Fragment:"..up_packet_num..":"..up_frag_num.. " Ack: "..down_packet_num..":"..down_frag_num)

	return true, up_packet_num, up_frag_num, is_last_frag
end

local function dis_data_request3(buffer, tree)
	if not buffer:len() == 1 then
		return false
	end

	tree:add(cmc_F,buffer(0,1))

	return true
end


local function dis_payload(buffer, tree, pinfo, maintree, packet_id, compressed)
	-- check if we have all the parts
	local last_frag_num
	for i = 0, 100 do
		frag_id = table.concat({packet_id,i},":")
		fragment = fragments[frag_id]
		-- if we are missing a fragment
		if not fragment then
			-- wait for fragment i of packet down_packet_num to arrive
			return true
		end

		-- if we have the last frag, we are good to go
		if fragment["is_last_frag"] then
			last_frag_num = i
			break
		end
	end

	-- now we know it is complete, rebuild it
	bytes = ByteArray.new()
	for i = 0, last_frag_num do
		frag_id = table.concat({packet_id,i},":")
		bytes:append(fragments[frag_id]["bytes"])
		fragments[frag_id] = nil
	end
	tree:add("aaa",bytes:tohex(true,":"))

	local data_buffer
	if compressed then
		local item = tree:add(buffer(),"Data package (zlib)")
		local comp_data_buffer = bytes:tvb("Reconstructed Payload (zlib)")
		data_buffer = comp_data_buffer():uncompress("Reconstructed Payload")

		if not data_buffer then
			item:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to expand data. Bad zlib?")
			return true
		end
	else
		tree:add(buffer(2),"Downstream package")
		data_buffer = bytes:tvb("Reconstructed Payload")
	end
		
	-- dissect the next layer
	local tun_header = data_buffer(0,2):uint()
	-- FIXME: add theses to tree and properties
	local protocol = data_buffer(2,2):uint()
	local dissector = ethertype_table:get_dissector(protocol)
	if (protocol) then
		if not dissector then
			--FIXME: item:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to expand data. Bad zlib?")
			tree:add("BAD proto!?", string.format("%04x", protocol))
		else
			-- let the next protocol fill it
			pinfo.cols.info:clear()
			pinfo.cols.info:clear_fence()
			pinfo.cols.protocol:clear()
			dissector:call(data_buffer(4):tvb(),pinfo,maintree)
		end
	end
	
	return true
end

local function dis_data_request4(buffer, tree, pinfo, maintree, up_packet_num, up_frag_num, is_last_frag, domain_name, user_id, is_reply)
	if not buffer or buffer:len()==0 then
		tree:add("NO DATA")
		return true
	end

	local packet_id = table.concat({user_id,domain_name,up_packet_num},":")
	local frag_id = table.concat({packet_id,up_frag_num},":")

	-- save the fragment (or the single packet for common implementation)
	fragments[frag_id] = {["bytes"]=buffer():bytes(), ["is_last_frag"]=is_last_frag}

	-- try to rebuild the fragment and dissect the payload
	return dis_payload(buffer(), tree, pinfo, maintree, packet_id, true)
end
local function dis_data_answer(buffer, tree, pinfo, maintree, domain_name, user_id)
	if buffer:len() < 2 then
		local item = tree:add(buffer(), "Downstream Data")
		item:add_expert_info(PI_MALFORMED, PI_ERROR, "Answer should, at least, have 2 bytes")
		return true
	end

	-- Downstream data starts with 2 byte header.
	--  7 654 3210 765 4321 0
	-- +-+---+----+---+----+-+
	-- |C|SSS|FFFF|DDD|GGGG|L|
	-- +-+---+----+---+----+-+
	--
	-- L = Last fragment in packet flag
	-- SS = Upstream packet sequence number
	-- FFFF = Upstream fragment number
	-- DDD = Downstream packet sequence number
	-- GGGG = Downstream fragment number
	-- C = Compression enabled for downstream packet

	-- FIXME: add properties

	local compressed = bit32.band(buffer(0,2):uint(),0x0001)
	local up_packet_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x7000),12)
	local up_frag_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x0f00),8)
	local down_packet_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x00e0),5)
	local down_frag_num = bit32.rshift(bit32.band(buffer(0,2):uint(),0x001E),1)
	local is_last_frag = bit32.rshift(bit32.band(buffer(0,2):uint(),0x0001),0)==1
	tree:add(buffer(0,1), "Compressed:",compressed)
	tree:add(buffer(0,1), "Upstream packet sequence number:",up_packet_num)
	tree:add(buffer(0,1), "Upstream fragment number:",up_frag_num)
	tree:add(buffer(1,1), "Downstream packet sequence number:",down_packet_num)
	tree:add(buffer(1,1), "Downstream fragment number:",down_frag_num)
	tree:add(buffer(1,1), "Last fragment in packet:",is_last_frag)
	
	-- FIXME: when fragments do not increase, it might be just an ack 
	pinfo.cols.info:set("Fragmented packet "..domain_name..'->User:'..tostring(user_id).." Fragment="..down_packet_num..":"..down_frag_num.. " Ack="..up_packet_num..":"..up_frag_num)

	-- Then payload data, which may be compressed.
	if buffer:len() <= 2 then
		return true
	end
	
	local packet_id = table.concat({domain_name,user_id,down_packet_num},":")
	local frag_id = table.concat({packet_id,down_frag_num},":")

	-- save the fragment (or the single packet for common implementation)
	fragments[frag_id] = {["bytes"]=buffer(2):bytes(), ["is_last_frag"]=is_last_frag}

	-- try to rebuild the fragment and dissect the payload
	return dis_payload(buffer(2), tree, pinfo, maintree, packet_id, compressed == 1)
end

-- parse a dnsquery ByteArray into a continuous ByteArray
local function dnsquery_parse(buffer)
	local input = buffer()
	local output = ByteArray.new()

	while input:len() > 0 do
		local comp_size = input(0,1):uint()
		output:append(input(1,comp_size):bytes())

		if input:len()-1-comp_size <= 0 then
			break
		end

		input=input(comp_size+1)
	end

	return output
end


function iodine.dissector(buffer,pinfo,tree)
	local dns_qry_name = dns_qry_name_f()
	local answer_field = dns_txt_f() or dns_data_f()
	local dns_response = dns_flags_response_f()

	if not dns_response then
		return
	end

	local is_response = dns_response.value

	local subtree
	subtree = tree:add(iodine,"IODINE tunnel over DNS")

	-- all valid DNS request/answer will contain a query name
	if not dns_qry_name then
		subtree.hidden = true
		return
	end

	-- FIXME: UTF-8 breaking test in Z command.
	local dns_qry_name_str = dns_qry_name.value

	-- first parse the query as a whole. We'll cut the domain afterwards
	local query_data
	local domain_name
	-- For known domains, manually cut the domain components (as the payload might include multiple components)
	for _domain_name, pkt in pairs(known_domains) do
		if dns_qry_name_str:sub(-#_domain_name) == _domain_name then
			query_data = dns_qry_name_str:sub(1,#dns_qry_name_str-#_domain_name-1)
			domain_name = _domain_name
			break
		end
	end

	-- If it is now known, just try with the first domain component
	if not query_data then
		query_data, domain_name = string.match(dns_qry_name_str, "^([^%.]+)%.(.*)")
	end

	-- Do not use #query_data as it might get confused with UTF-8 chars
	query_data_len = dns_qry_name.len-#domain_name-3
	local domtree = subtree:add(domain_F, dns_qry_name.range(dns_qry_name.len-#domain_name-1, #domain_name), domain_name)
	local clitree = subtree:add(buffer(dns_qry_name.offset+1, query_data_len), "Upstream")
	local query_tvb

	-- reparse domain components as bytearray() without dots or string parsing
	local query_bytes = dnsquery_parse(dns_qry_name.range(0, query_data_len+1))

	local answer_data
	local answer_tvb
	if is_response then
		if answer_field then
			answer_data = answer_field.range:raw()
			-- FIXME: breaks in reasseambled TCP
			--srvtree = subtree:add(buffer(answer_field.offset, answer_field.len), "Downstream")
			srvtree = subtree:add(answer_field.range, "Downstream")
		else
			srvtree = subtree:add("Downstream")
		end
	end
	
	pinfo.cols.protocol = "IODINE"
	-- let other protocols replace the Info
	pinfo.cols.info:clear_fence()

	-- VERSION QUERY
	-- First byte v or V
	if string.lower(dns_qry_name.range(1,1):raw())=="v" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"VERSION")

		query_tvb, enctree = dis_base32(dns_qry_name.range(2, query_data_len-1), clitree)
		if not dis_version_request(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		
		known_domains[domain_name]=pinfo.number

		-- VERSION ANSWER
		if answer_field then
			srvtree:add(type_F,"VERSION ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			if not dis_version_answer(answer_tvb, enctree)  then
				subtree.hidden = true
				return
			end
		end

	-- LOGIN
	-- First byte l or L
	elseif string.lower(dns_qry_name.range(1,1):raw())=="l" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"LOGIN")
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, query_data_len-1), clitree)
		if not dis_login_request(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		
		known_domains[domain_name]=pinfo.number
		
		-- LOGIN ANSWER
		if answer_field then
			srvtree:add(type_F,"LOGIN ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			if not dis_login_answer(answer_tvb, enctree)  then
				subtree.hidden = true
				return
			end
		end

	-- IP REQUEST
	-- First byte i or I
	elseif string.lower(dns_qry_name.range(1,1):raw())=="i" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"IP REQUEST")
		-- 	5 bits coded as Base32 char, meaning userid
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, 1), clitree, 5)
		if not dis_ip_request1(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		--	CMC as 3 Base32 chars
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+3, 3), clitree, 15)
		if not dis_ip_request2(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		
		known_domains[domain_name]=pinfo.number
		
		-- IP ANSWER
		if answer_field then
			srvtree:add(type_F,"IP ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			if not dis_ip_answer(answer_tvb, enctree)  then
				subtree.hidden = true
				return
			end
		end

	-- UPSTREAM CODEC CHECK
	-- First byte z or Z
	elseif string.lower(dns_qry_name.range(1,1):raw())=="z" then
		enctree = clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"UPSTREAM CODEC CHECK REQUEST")
		query_tvb = buffer(dns_qry_name.offset+2, query_data_len-3)
		if not dis_upcodec_check_request(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		-- LOGIN ANSWER
		if answer_field then
			-- FIXME: add check that the request matched
			-- 	The requested domain copied raw, in the lowest-grade downstream codec
			-- 	available for the request type.
			srvtree:add(type_F,"UPSTREAM CODEC CHECK ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			-- it seems that the last byte is bogus
			answer_tvb = answer_tvb(0, answer_tvb:len()-1)
			if not dis_upcodec_check_answer(answer_tvb, enctree, buffer(dns_qry_name.offset+1,answer_tvb:len()))  then
				subtree.hidden = true
				return
			end
		end

	-- DOWNSTREAM CODEC CHECK REQUEST
	-- First byte y or Y
	elseif string.lower(dns_qry_name.range(1,1):raw())=="y" then
		enctree = clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"DOWNSTREAM CODEC CHECK REQUEST")

		--	1 char, meaning downstream codec to use
		--query_tvb, enctree = buffer(dns_qry_name.offset+2, 1)
		query_tvb = buffer(dns_qry_name.offset+2, 1)
		if not dis_downcodec_check_request1(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		-- 	5 bits coded as Base32 char, meaning check variant
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+3, 1), clitree, 5)
		if not dis_downcodec_check_request2(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		--	CMC as 3 Base32 chars
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+4, 3), clitree, 15)
		if not dis_ip_request2(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		
		known_domains[domain_name]=pinfo.number

		-- DOWNSTREAM CODEC CHECK ANSWER
		if answer_field then
			srvtree:add(type_F,"DOWNSTREAM CODEC CHECK ANSWER")
			if answer_data == "BADCODEC" then
				srvtree:add(result_F,buffer(answer_field.offset, answer_field.len))
			else
				answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
				if not dis_downcodec_check_answer(answer_tvb, enctree)  then
					--subtree.hidden = true
					return
				end
			end
		end

	--FIXME: not tested
	-- First byte s or S
	elseif string.lower(dns_qry_name.range(1,1):raw())=="s" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"SWITCH CODEC REQUEST")
		-- 	5 bits coded as Base32 char, meaning userid
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, 1), clitree, 5)
		if not dis_ip_request1(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+3, 1), clitree)
		if not dis_switch_codec_request2(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		--	CMC as 3 Base32 chars
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+3, 3), clitree, 15)
		if not dis_ip_request2(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		-- SWITCH CODEC ANSWER
		if answer_field then
			srvtree:add(type_F,"SWITCH CODEC ANSWER")
			-- Plain text?
			-- Name of codec if accepted. After this all upstream data packets must
			-- be encoded with the new codec.
			-- BADCODEC if not accepted. Client must then revert to previous codec
			-- BADLEN if length of query is too short
		end
	
	-- First byte o or O
	elseif string.lower(dns_qry_name.range(1,1):raw())=="o" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"OPTIONS REQUEST")
		-- 	5 bits coded as Base32 char, meaning userid
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, 1), clitree, 5)
		if not dis_ip_request1(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end

		--	1 char, meaning option
		if not dis_options_request2(buffer(dns_qry_name.offset+3, 1), clitree) then
			subtree.hidden = true
			return
		end

		--	CMC as 3 Base32 chars
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+3, 3), clitree, 15)
		if not dis_ip_request2(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		-- OPTION ANSWER
		if answer_field then
			srvtree:add(type_F,"OPTION ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			if not dis_options_answer(answer_tvb, enctree)  then
				subtree.hidden = true
				return
			end
		end

	-- First byte r or R
	elseif string.lower(dns_qry_name.range(1,1):raw())=="r" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"PROBE DOWNSTREAM FRAGMENT SIZE REQUEST")
		-- 	15 bits coded as 3 Base32 chars
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, 3), clitree, 15)
		if not dis_probe_fragsize_request1(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		-- Then follows a long random query which contents does not matter
		clitree:add(buffer(dns_qry_name.offset+5,query_data_len-4),"Payload")

		-- PROBE DOWNSTREAM FRAGMENT SIZE ANSWER
		if is_response then
			srvtree:add(type_F,"PROBE DOWNSTREAM FRAGMENT SIZE ANSWER")
			-- Server answer is empty
			if not answer_field then
				srvtree:add(result_F, "NO ANSWER")
			-- BADFRAG if requested length not accepted.
			elseif answer_data == "BADFRAG" then
				srvtree:add(result_F,buffer(answer_field.offset, answer_field.len))
			else
				-- Requested number of bytes as a response.
				answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
				if not dis_probe_fragsize_answer(answer_tvb, enctree) then
					subtree.hidden = true
					return
				end
			end
		end
		
	-- First byte n or N
	elseif string.lower(dns_qry_name.range(1,1):raw())=="n" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"SET DOWNSTREAM FRAGMENT SIZE REQUEST")
		-- Rest encoded with base32
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, query_data_len-1), clitree)
		if not dis_down_fragsize_request(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end
		-- SET DOWNSTREAM FRAGMENT SIZE ANSWER
		if answer_field then
			srvtree:add(type_F,"SET DOWNSTREAM FRAGMENT SIZE ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			if not dis_down_fragsize_answer(answer_tvb, enctree)  then
				subtree.hidden = true
				return
			end
		end

	-- First byte p or P
	elseif string.lower(dns_qry_name.range(1,1):raw())=="p" then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"PING REQUEST")
		-- Rest encoded with Base32
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, query_data_len-1), clitree)
		if not dis_ping_request(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end

		-- PING ANSWER
		if answer_field then
			srvtree:add(type_F,"PING ANSWER")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)
			if not dis_ping_answer(answer_tvb, enctree)  then
				subtree.hidden = true
				return
			end
		end

	-- 	Upstream data packet starts with 1 byte ASCII hex coded user byte	
	elseif string.lower(dns_qry_name.range(1,1):raw()):match("[0-9A-F]") then
		clitree:add(type_F,buffer(dns_qry_name.offset+1,1),"UPSTREAM DATA PACKAGE")

		-- 4 bits coded as Base32 char, meaning userid
		query_tvb, enctree = dis_hex(buffer(dns_qry_name.offset+1, 1), clitree)
		local ok, user_id
		ok, user_id = dis_ip_request1(query_tvb, enctree) 
		if not ok then
			subtree.hidden = true
			return
		end

		-- then 3 bytes Base32 encoded header
		query_tvb, enctree = dis_base32(buffer(dns_qry_name.offset+2, 3), clitree, 15)
		local ok, up_packet_num, up_frag_num, is_last_frag = dis_data_request2(query_tvb, enctree, pinfo, domain_name, user_id)
		if not ok  then
			subtree.hidden = true
			return
		end

		-- then 1 char data-CMC;
		query_tvb, enctree = dis_dict36(buffer(dns_qry_name.offset+5, 1), clitree, 5)
		if not dis_data_request3(query_tvb, enctree)  then
			subtree.hidden = true
			return
		end

		-- then comes the payload data, encoded with the chosen upstream codec.
		-- FIXME: get the last set codec, not only base32
		query_tvb, enctree = dis_base32(dns_qry_name.range(6, query_data_len-5), clitree, nil, query_bytes:subset(5, query_bytes:len()-5))
		if not dis_data_request4(query_tvb, enctree, pinfo, tree, up_packet_num, up_frag_num, is_last_frag, domain_name, user_id, answer_field) then
			subtree.hidden = true
			return
		end
		-- DATA ANSWER
		if answer_field then
			srvtree:add(type_F,buffer(dns_qry_name.offset+1,1),"DOWNSTREAM DATA PACKAGE")
			answer_tvb, enctree = dis_data(buffer(answer_field.offset, answer_field.len), srvtree)

			if not dis_data_answer(answer_tvb, enctree, pinfo, tree, domain_name, user_id) then
	                        subtree.hidden = true
        	                return
			end
		end
	else
		pinfo.cols.protocol = "DNS"
		subtree.hidden = true
		return
	end

end

register_postdissector(iodine)
