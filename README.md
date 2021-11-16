# wireshark-dissectors
Extra wireshark disserctors

This repo contains extra wireshark dissectors written in lua:

Marvell_EDSA: Ethertype DSA tagging (Marvell)

![image](https://user-images.githubusercontent.com/836788/139790677-9288cf72-d31f-467e-afad-a006b1dd6c9d.png)

Realtek_L2: Realtek Layer 2 protocols (only DSA tag protocol 04)

***TODO: add image***

To install, simply copy the lua file to your "Personal ..." or "Global Lua Plugins" directory (like ~/.local/lib/wireshark/plugins/).
Restart wireshark or press ctrl+shift+L.
