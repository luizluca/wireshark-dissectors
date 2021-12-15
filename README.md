# wireshark-dissectors
Extra wireshark disserctors

This repo contains extra wireshark dissectors written in lua:

Marvell_EDSA: Ethertype DSA tagging (Marvell)

![image](https://user-images.githubusercontent.com/836788/139790677-9288cf72-d31f-467e-afad-a006b1dd6c9d.png)

Realtek_L2: Realtek Layer 2 protocols (only DSA tag protocol 04)

![image](https://user-images.githubusercontent.com/836788/146117738-e7574c3b-34fe-4185-aa80-7c938ef50a07.png)

To install, simply copy the lua file to your "Personal ..." or "Global Lua Plugins" directory (like ~/.local/lib/wireshark/plugins/).
Restart wireshark or press ctrl+shift+L.

Wireshark/pcap do not understand the Link Type for DSA rtl8_4. There is a pending libpcap patch but might still require more changes to
tcpdump and wireshark. For now, edit the pcap file and replace position 0x14 to 0x01 and 0x15 to 0x00 (0x0001 is EN10).
