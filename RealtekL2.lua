-- vim: noai:ts=4:sw=4:expandtab
edsa = Proto("RealtekL2",  "Realtek Layer 2 Protocols 2")

local DSA_HLEN_04_8 = 8
local DSA_HLEN_04_4 = 4
local DSA_HLEN_A = 4
local ETHER_TYPE_LEN = 2

local DSA_PROTO_04 = 0x04
local DSA_PROTO_9 = 0x9
local DSA_PROTO_A = 0xa

local DSA_REASON_FORWARD  = 0x00
local DSA_REASON_TRAPPED = 0x80
local DSA_REASON = {
    [DSA_REASON_FORWARD] = "Forward",
    [DSA_REASON_TRAPPED] = "Trapped",
}

local DSA_CODE_MGMT_TRAP     = 0
local DSA_CODE_FRAME2REG     = 1
local DSA_CODE_IGMP_MLD_TRAP = 2
local DSA_CODE_POLICY_TRAP   = 3
local DSA_CODE_ARP_MIRROR    = 4
local DSA_CODE_POLICY_MIRROR = 5
local DSA_CODE_RESERVED_6    = 6
local DSA_CODE_RESERVED_7    = 7
local DSA_CODE = {
    [DSA_CODE_MGMT_TRAP]     = "MGMT_TRAP",
    [DSA_CODE_FRAME2REG]     = "FRAME2REG",
    [DSA_CODE_IGMP_MLD_TRAP] = "IGMP_MLD_TRAP",
    [DSA_CODE_POLICY_TRAP]   = "POLICY_TRAP",
    [DSA_CODE_ARP_MIRROR]    = "ARP_MIRROR",
    [DSA_CODE_POLICY_MIRROR] = "POLICY_MIRROR",
    [DSA_CODE_RESERVED_6]    = "RESERVED_6",
    [DSA_CODE_RESERVED_7]    = "RESERVED_7",
}
local DSA_DIRECTION = {
        [0] = "From egress source port",
        [1] = "From ingress source port",
}

local pf_proto_id         = ProtoField.uint8  ("dsa_ethertype_rtk.protocol", "Tag Version", base.HEX)
local pf_reason_id        = ProtoField.uint8  ("dsa_ethertype_rtk.reason", "Reason", base.HEX, DSA_REASON)
local pf_fid_en_id        = ProtoField.bool   ("dsa_ethertype_rtk.fid_enabled", "FID Enabled", 32, null, 0x80000000)
local pf_fid_id           = ProtoField.uint32 ("dsa_ethertype_rtk.fid", "FID", base.HEX, null, 0x70000000)
local pf_pri_en_id        = ProtoField.bool   ("dsa_ethertype_rtk.priority_enabled", "Priority Enabled", 32, null, 0x08000000)
local pf_pri_id           = ProtoField.uint32 ("dsa_ethertype_rtk.priority", "Priority", base.HEX, null, 0x07000000)
local pf_keep_id          = ProtoField.bool   ("dsa_ethertype_rtk.keep_vlan", "Keep VLAN Tag", 32, null, 0x00800000)
local pf_vlan_en_id       = ProtoField.bool   ("dsa_ethertype_rtk.vlan_enable", "Enable VLAN", 32, null, 0x00400000)
local pf_learn_dis        = ProtoField.bool   ("dsa_ethertype_rtk.dont_learn_mac", "Disable Source MAC Learn", 32, null, 0x00200000)
local pf_vidx             = ProtoField.uint32 ("dsa_ethertype_rtk.vidx", "VLAN index", base.DEC, null, 0x001F0000)
local pf_allowance        = ProtoField.bool   ("dsa_ethertype_rtk.allowance", "Allowance", 32, null, 0x00008000)
-- this is a single byte value (up to 15)
local pf_txport           = ProtoField.uint32 ("dsa_ethertype_rtk.tx_port", "Transmitter Port", base.DEC, null, 0x0000000f)
-- this is a bitmap, up to 11
local pf_rxport_mask      = ProtoField.uint32 ("dsa_ethertype_rtk.rx_port_mask", "Receiver Port Mask", base.HEX, null, 0x000007fff)
local pf_ethertype_id     = ProtoField.uint16 ("dsa_ethertype_rtk.ether_type", "Ethernet Type", base.HEX)

edsa.fields = { pf_proto_id, pf_reason_id, pf_fid_en_id, pf_fid_id, pf_pri_en_id, pf_pri_id, pf_keep_id, pf_vlan_en_id, pf_learn_dis, pf_vidx, pf_allowance, pf_txport, pf_rxport_mask, pf_ethertype_id }
dsEtherType = DissectorTable.get("ethertype")

function bitmask2num(bitmask, numbits)
    local ret=""
    for num=0,numbits-1 do
        if (bitmask % 2 == 1) then
            ret=ret..","..num
        end
        bitmask=bitmask/2
    end
    return ret:sub(2)
end

function dissector9(tvbuf,pktinfo,root)
    local tree = root:add(edsa, tvbuf:range(0,DSA_HLEN_9 + ETHER_TYPE_LEN), "Realtek Ethertype DSA tagging")
    tree:add("Not implemented yet")
    -- -------------------------------------------------
    -- | MAC DA | MAC SA | 0x8899 | 2-byte tag  | Type |
    -- -------------------------------------------------
    --
    -- The 2-byte tag format in tag_rcv:
    --       +------+------+------+------+------+------+------+------+
    -- 15: 8 |   Protocol number (0x9)   |  Priority   |  Reserved   |
    --       +------+------+------+------+------+------+------+------+
    --  7: 0 |             Reserved             | Source port number |
    --       +------+------+------+------+------+------+------+------+
    --
    -- The 2-byte tag format in tag_xmit:
    --       +------+------+------+------+------+------+------+------+
    -- 15: 8 |   Protocol number (0x9)   |  Priority   |  Reserved   |
    --       +------+------+------+------+------+------+------+------+
    --  7: 0 |  Reserved   |          Destination port mask          |
    --       +------+------+------+------+------+------+------+------+
    local consumed_len = DSA_HLEN_9 + ETHER_TYPE_LEN
    return dsOneEtherType:call(tvbuf:bytes(8,tvbuf:len()-consumed_len):tvb("test"), pktinfo, root) + consumed_len
end

function dissectorA(tvbuf,pktinfo,root)
    -- -------------------------------------------------
    -- | MAC DA | MAC SA | 0x8899 | 2 bytes tag | Type |
    -- -------------------------------------------------
    local tree = root:add(edsa, tvbuf:range(0,DSA_HLEN_A), "Realtek Ethertype DSA tagging")
    tree:add("Not implemented yet")
    local consumed_len = DSA_HLEN_A
    return dsOneEtherType:call(tvbuf:bytes(8,tvbuf:len()-consumed_len):tvb("test"), pktinfo, root) + consumed_len
end

function dissector04(tvbuf,pktinfo,root)
--      7   6   5   4   3   2   1   0
--   .   .   .   .   .   .   .   .   .
--   +---+---+---+---+---+---+---+---+
--   |   Ether Destination Address   |
--   +---+---+---+---+---+---+---+---+
--   |     Ether Source Address      |
--   +---+---+---+---+---+---+---+---+  --
--   |   Realktek Ether Type [15:8]  |  |
--   +---+---+---+---+---+---+---+---+  |
--   |   Realktek Ether Type [7:0]   |  |
--   +---+---+---+---+---+---+---+---+  |
--   |            Protocol           |  |
--   +---+---+---+---+---+---+---+---+  |
--   |             Reason            |  |
--   +---+---+---+---+---+---+---+---+  | EDSA tag
--   | b1|EncFID[2:0]| b2| PRI [2:0] |  |
--   +---+---+---+---+---+---+---+---+  |
--   | b3| b4| b5|    VIDX [4:0]     |  |
--   +---+---+---+---+---+---+---+---+  |
--   | b6|         TX/RX[14:8]       |  |
--   +---+---+---+---+---+---+---+---+  |
--   |           TX/RX[7:0]          |  |
--   +---+---+---+---+---+---+---+---+  --
--   |           Ether Type          |
--   +---+---+---+---+---+---+---+---+
--   .   .   .   .   .   .   .   .   .
--
    local dsa_len = DSA_HLEN_04_8
    local tree
    local etherTypebr

    tree = root:add(edsa, tvbuf:range(0,dsa_len), "Realtek Ethertype DSA tagging")
    tree:add(pf_proto_id, tvbuf:range(0,1))

    if (dsa_len == DSA_HLEN_04_8) then
        tree:add(pf_reason_id, tvbuf:range(1,1))

        local tvbr = tvbuf:range(2,4)
        tree:add(pf_fid_en_id,tvbr)
        tree:add(pf_fid_id,tvbr)
        tree:add(pf_pri_en_id,tvbr)
        tree:add(pf_pri_id,tvbr)
        tree:add(pf_keep_id,tvbr)
        tree:add(pf_vlan_en_id,tvbr)
        tree:add(pf_learn_dis,tvbr)
        tree:add(pf_vidx,tvbr)
        tree:add(pf_allowance,tvbr)
        -- How to select one of them?!
        tree:add(pf_txport,tvbr)
        tree:add(pf_rxport_mask,tvbr:bitfield(17,15),null,"ports: "..bitmask2num(tvbr:bitfield(17,15),15))

        etherTypebr = tvbuf:range(6,2)

    elseif (dsa_len == DSA_HLEN_04_4) then
        local tvbr = tvbuf:range(1,1)
        tree:add(pf_txport, tvbr)
        --tree:add(pf_rxport_mask,tvbr:bitfield(17,15),null,"ports: "..bitmask2num(tvbr:bitfield(17,15),15))
        etherTypebr = tvbuf:range(2,2)
    else
        tree:add("Unknown tag size!")
        return 0
    end

    tree:add(pf_ethertype_id, etherTypebr)
    dsOneEtherType = dsEtherType:get_dissector(etherTypebr:uint())

    return dsOneEtherType:call(tvbuf:bytes(dsa_len,tvbuf:len()-dsa_len):tvb("Realtek Ethertype DSA tagging"), pktinfo, root) + dsa_len
end

function edsa.dissector(tvbuf,pktinfo,root)
    -- 4 bit version 
    local proto = tvbuf:range(0,1):bitfield(0,4)
    if proto == DSA_PROTO_A then
	-- RTL8366RB DSA protocol
        return dissectorA(tvbuf,pktinfo,root)
    elseif proto == 0x0 then
	-- 8 bit version
	proto = tvbuf:range(0,1):bitfield(0,8)
	if proto == DSA_PROTO_04 then
	    return dissector04(tvbuf,pktinfo,root)
	end
    elseif proto == DSA_PROTO_9 then
        return dissector9(tvbuf,pktinfo,root)
    elseif proto == 0x1 then
        -- Realtek Remote Control protocol (RRCP)
    elseif proto == 0x2 then
        -- seems to be used for loopback testing
    elseif proto == 0x3 then
        -- seems to be used for loopback testing
    end
    local tree = root:add(edsa, tvbuf:range(0,1))
    tree:add("Unknown Realtek Ethertype DSA Tag Version 0x" .. string.format("%02x", proto))
    return 0
end

do
        dsEtherType:add(0x8899, edsa)
end
