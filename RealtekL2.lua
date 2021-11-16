edsa = Proto("RealtekL2",  "Realtek Layer 2 Protocols")

local DSA_HLEN_4 = 6
local DSA_HLEN_A = 2
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
local pf_fid_en_id        = ProtoField.uint16 ("dsa_ethertype_rtk.fid_enabled", "FID Enabled", base.HEX, null, 0x8000)
local pf_reserved         = ProtoField.uint16 ("dsa_ethertype_rtk.reserved", "Reserved", base.HEX, null, 0x4000)
local pf_fid_id           = ProtoField.uint16 ("dsa_ethertype_rtk.fid", "FID", base.HEX, null, 0x3000)
local pf_pri_en_id        = ProtoField.uint16 ("dsa_ethertype_rtk.priority_enabled", "Priority Enabled", base.HEX, null, 0x0800)
local pf_pri_id           = ProtoField.uint16 ("dsa_ethertype_rtk.priority", "Priority", base.HEX, null, 0x0700)
local pf_keep_id          = ProtoField.uint16 ("dsa_ethertype_rtk.keep_vlan", "Keep VLAN Tag", base.HEX, null, 0x0080)
local pf_reserved2        = ProtoField.uint16 ("dsa_ethertype_rtk.reserved2", "Reserved", base.HEX, null, 0x0040)
local pf_learn_dis        = ProtoField.uint16 ("dsa_ethertype_rtk.learn_mac", "Learn Source MAC", base.HEX, null, 0x0020)
local pf_reserved3        = ProtoField.uint16 ("dsa_ethertype_rtk.reserved3", "Reserved", base.HEX, null, 0x001F)
local pf_allowance        = ProtoField.uint16 ("dsa_ethertype_rtk.allowance", "Allowance", base.HEX, null, 0x8000)
-- this is a single byte value (up to 15)
local pf_txport           = ProtoField.uint16 ("dsa_ethertype_rtk.tx_port", "transmitter Port", base.HEX, null, 0x000f)
-- this is a bitmap, up to 11
local pf_rxport_mask      = ProtoField.uint16 ("dsa_ethertype_rtk.rx_port_mask", "Receiver Port Mask", base.HEX, null, 0x07ff)
local pf_ethertype_id     = ProtoField.uint16 ("dsa_ethertype_rtk.ether_type", "Ethernet Type", base.HEX)

edsa.fields = { pf_proto_id, pf_reason_id, pf_fid_en_id, pf_reserved, pf_fid_id, pf_pri_en_id, pf_pri_id, pf_keep_id, pf_reserved2, pf_learn_dis, pf_reserved3, pf_allowance, pf_txport, pf_rxport_mask, pf_ethertype_id }
dsEtherType = DissectorTable.get("ethertype")

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
    local tree = root:add(edsa, tvbuf:range(0,DSA_HLEN_A + ETHER_TYPE_LEN), "Realtek Ethertype DSA tagging")
    tree:add("Not implemented yet")
    local consumed_len = DSA_HLEN_A + ETHER_TYPE_LEN
    return dsOneEtherType:call(tvbuf:bytes(8,tvbuf:len()-consumed_len):tvb("test"), pktinfo, root) + consumed_len
end

function dissector04(tvbuf,pktinfo,root)
    --  -------------------------------------------
    --  | MAC DA | MAC SA | 8 byte tag | Type | ...
    --  -------------------------------------------
    --     _______________/            \______________________________________
    --    /                                                                   \
    --  0                                  7|8                                 15
    --  |-----------------------------------+-----------------------------------|---
    --  |                               (16-bit)                                | ^
    --  |                       Realtek EtherType [0x8899]                      | |
    --  |-----------------------------------+-----------------------------------| 8
    --  |              (8-bit)              |              (8-bit)              |
    --  |          Protocol [0x04]          |              REASON               | b
    --  |-----------------------------------+-----------------------------------| y
    --  |   (1)  | (1) | (2) |   (1)  | (3) | (1)  | (1) |    (1)    |   (5)    | t
    --  | FID_EN |  X  | FID | PRI_EN | PRI | KEEP |  X  | LEARN_DIS |    X     | e
    --  |-----------------------------------+-----------------------------------| s
    --  |   (1)  |                       (15-bit)                               | |
    --  |  ALLOW |                        TX/RX                                 | v
    --  |-----------------------------------+-----------------------------------|---
    --
    -- With the following field descriptions:
    --
    --    field      | description
    --   ------------+-------------
    --    Realtek    | 0x8899: indicates that this is a proprietary Realtek tag;
    --     EtherType |         note that Realtek uses the same EtherType for
    --               |         other incompatible tag formats (e.g. tag_rtl4_a.c)
    --    Protocol   | 0x04: indicates that this tag conforms to this format
    --    X          | reserved
    --   ------------+-------------
    --    REASON     | reason for forwarding packet to CPU
    --               | 0: packet was forwarded or flooded to CPU
    --               | 80: packet was trapped to CPU
    --    FID_EN     | 1: packet has an FID
    --               | 0: no FID
    --    FID        | FID of packet (if FID_EN=1)
    --    PRI_EN     | 1: force priority of packet
    --               | 0: don't force priority
    --    PRI        | priority of packet (if PRI_EN=1)
    --    KEEP       | preserve packet VLAN tag format
    --    LEARN_DIS  | don't learn the source MAC address of the packet
    --    ALLOW      | 1: treat TX/RX field as an allowance port mask, meaning the
    --               |    packet may only be forwarded to ports specified in the
    --               |    mask
    --               | 0: no allowance port mask, TX/RX field is the forwarding
    --               |    port mask
    --    TX/RX      | TX (switch->CPU): port number the packet was received on
    --               | RX (CPU->switch): forwarding port mask (if ALLOW=0)
    local tree = root:add(edsa, tvbuf:range(0,DSA_HLEN_4 + ETHER_TYPE_LEN), "Realtek Ethertype DSA tagging")
    tree:add(pf_proto_id, tvbuf:range(0,1))
    tree:add(pf_reason_id, tvbuf:range(1,1))
    local tvbr = tvbuf:range(2,2)
    tree:add(pf_fid_en_id,tvbr)
    tree:add(pf_reserved,tvbr)
    tree:add(pf_fid_id,tvbr)
    tree:add(pf_pri_en_id,tvbr)
    tree:add(pf_pri_id,tvbr)
    tree:add(pf_keep_id,tvbr)
    tree:add(pf_reserved2,tvbr)
    tree:add(pf_learn_dis,tvbr)
    tree:add(pf_reserved3,tvbr)

    local tvbr = tvbuf:range(4,2)
    tree:add(pf_allowance,tvbr)
    -- How to select one of them?!
    tree:add(pf_txport,tvbr)
    tree:add(pf_rxport_mask,tvbr)

    local etherTypebr = tvbuf:range(6,2)
    tree:add(pf_ethertype_id, etherTypebr)
    dsOneEtherType = dsEtherType:get_dissector(etherTypebr:uint())
    local consumed_len = DSA_HLEN_4 + ETHER_TYPE_LEN
    return dsOneEtherType:call(tvbuf:bytes(8,tvbuf:len()-consumed_len):tvb("test"), pktinfo, root) + consumed_len
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
