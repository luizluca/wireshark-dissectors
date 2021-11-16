edsa = Proto("Marvell_EDSA",  "Marvell Ethertype DSA tagging")

local DSA_HLEN = 4
local ZERO_LEN = 2
local ETHER_TYPE_LEN = 2
local DSA_CMD_TO_CPU     = 0x0
local DSA_CMD_FROM_CPU   = 0x1
local DSA_CMD_TO_SNIFFER = 0x2
local DSA_CMD_FORWARD    = 0x3
local DSA_CMD = {
        [DSA_CMD_TO_CPU]     = "To CPU",
        [DSA_CMD_FROM_CPU]   = "From CPU",
        [DSA_CMD_TO_SNIFFER] = "To Sniffer",
        [DSA_CMD_FORWARD]    = "Forward",
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

local pf_zero_id          = ProtoField.new    ("Reserved", "marvell_dsa_ethertype.zero", ftypes.NONE)
local pf_cmd_id           = ProtoField.uint32 ("marvell_dsa_ethertype.cmd", "DSA Command", base.HEX, DSA_CMD, 0xc0000000)
local pf_tagged_id        = ProtoField.uint32 ("marvell_dsa_ethertype.tagged", "Tagged", base.DEC, null, 0x20000000)

local pf_source_device_id = ProtoField.uint32 ("marvell_dsa_ethertype.src_device","Source Device", base.DEC, null, 0x1f000000)
local pf_source_port_id   = ProtoField.uint32 ("marvell_dsa_ethertype.src_port","Source Port", base.DEC, null, 0x00f80000)
local pf_source_trunk_id  = ProtoField.uint32 ("marvell_dsa_ethertype.src_trunk","Source Trunk", base.DEC, null, 0x00f80000)
local pf_dest_device_id   = ProtoField.uint32 ("marvell_dsa_ethertype.dst_device","Destination Device", base.DEC, null, 0x1f000000)
local pf_dest_port_id     = ProtoField.uint32 ("marvell_dsa_ethertype.dst_port","Destination Port", base.DEC, null, 0x00f80000)

local pf_direction_id     = ProtoField.uint32 ("marvell_dsa_ethertype.direction","Direction", base.DEC, DSA_DIRECTION, 0x00040000)
local pf_code_id          = ProtoField.uint32 ("marvell_dsa_ethertype.code", "CPU Code", base.HEX, DSA_CODE, 0x03100000)
local pf_cfi_id           = ProtoField.uint32 ("marvell_dsa_ethertype.cfi", "Canonical Format Indicator (CFI) Code", base.DEC, null, 0x00010000)
local pf_vlan_pri_id      = ProtoField.uint32 ("marvell_dsa_ethertype.vlan_priority","VLAN Prioriry", base.DEC, null, 0x0000e000)
local pf_vlan_id_id       = ProtoField.uint32 ("marvell_dsa_ethertype.vlan_id","VLAN ID", base.DEC, null, 0x00000fff)
local pf_ethertype_id     = ProtoField.uint16 ("marvell_dsa_ethertype.ether_type", "Ethernet Type", base.HEX)

edsa.fields = { pf_zero_id, pf_tag_id, pf_cmd_id, pf_tagged_id, pf_source_device_id, pf_source_port_id, pf_source_trunk_id, pf_cfi_id,
                pf_dest_device_id, pf_dest_port_id, pf_direction_id, pf_code_id, pf_vlan_pri_id, pf_vlan_id_id, pf_ethertype_id }
dsEtherType = DissectorTable.get("ethertype")

function edsa.dissector(tvbuf,pktinfo,root)

    local tree = root:add(edsa, tvbuf:range(0,ZERO_LEN + DSA_HLEN + ETHER_TYPE_LEN))
    tree:add(pf_zero_id, tvbuf:range(0,2))
    local tvbr = tvbuf:range(2,4)
    
    --0                          1                          2                            3  
    --[ c1 c0 t0 d4 d3 d2 d1 d0 ][ p4 p3 p2 p1 p0 c2 c1 f0 ][ r2 r1 r0 c0 v11 v10 v9 v8 ][ v7 v6 v5 v4 v3 v2 v1 v0]
    local tagbr = tvbr:range(0,4)
    local cmd = tvbr:bitfield(0,2)
    tree:add(pf_cmd_id, tagbr)           -- c1c0
    local tagged = tvbr:bitfield(2,1)
    tree:add(pf_tagged_id,tagbr)        -- t0

    local egress = 0
    if cmd == DSA_CMD_FROM_CPU then
        egress=1
    elseif cmd == DSA_CMD_TO_SNIFFER then
        egress=tvbr:bitfield(13,1)
    end
    -- how to differ Forward DSA tag frame mode (egress/ingress)?

    local trunk = 0
    if cmd == DSA_CMD_FORWARD then
        trunk=tvbr:bitfield(13,1)
    end

    if egress == 1 then
        tree:add(pf_dest_device_id, tagbr) -- d4d3d2d1d0
        tree:add(pf_dest_port_id, tagbr)   -- p4p3p2p1p0
    else
        tree:add(pf_source_device_id, tagbr) -- d4d3d2d1d0
        if cmd == DSA_CMD_FORWARD and trunk == 1 then
            tree:add(pf_source_trunk_id, tagbr)   -- p4p3p2p1p0
        else
            tree:add(pf_source_port_id, tagbr)   -- p4p3p2p1p0
        end
    end

    if cmd == DSA_CMD_TO_SNIFFER then
       tree:add(pf_direction_id, tagbr) -- i0
    end

    if cmd == DSA_CMD_TO_CPU then
        c2=tvbr:bitfield(13,1)
        c1=tvbr:bitfield(14,1)
        c0=tvbr:bitfield(19,1)
        -- https://www.tcpdump.org/linktypes/LINKTYPE_DSA_TAG_DSA.html
        -- This docs says code is c1f0c0 but kernel tag code uses c2c1c0 and f0 is actually CFI!
        code=c2*4+c1*2+c0  -- c2c1c0
        -- Mask was breaking the value as 01...0 was converted to 010001b and not 010b
        tree:add(pf_code_id, tvbr:range(1,2),0x1ff,".... .... .... ."..c2..c1..". ..."..c0.." .... .... .... = "..DSA_CODE[code]..": "..code)
    end

    local consumed_len = ZERO_LEN + DSA_HLEN + ETHER_TYPE_LEN
    if tagged == 1 then
        tree:add(pf_cfi_id, tagbr) -- f0
        tree:add(pf_vlan_pri_id, tagbr) -- r2r1r0
        tree:add(pf_vlan_id_id, tagbr) -- v11v10v9v8v7v6v5v4v3v2v1v0
    end

    local etherTypebr = tvbuf:range(6,2)

    tree:add(pf_ethertype_id, etherTypebr)   -- p4p3p2p1p0
    dsOneEtherType = dsEtherType:get_dissector(etherTypebr:uint())
    return dsOneEtherType:call(tvbuf:bytes(8,tvbuf:len()-consumed_len):tvb("test"), pktinfo, root) + consumed_len
end

do
    dsEtherType:add(0xdada, edsa)
end
