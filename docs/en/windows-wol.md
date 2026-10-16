# Configuring Wake-on-LAN (WOL) on Windows

## 1. What it does

Wake-on-LAN (WOL) wakes a fully powered-off Windows machine by sending a **Magic Packet** over the LAN.

Core principle: after a normal Windows soft shutdown, the NIC keeps its 5V standby power and continues listening for LAN packets; on receiving a standard magic packet it triggers the motherboard to power up.

## 2. NIC settings in Device Manager

Path: right-click Start → Device Manager → Network adapters → **wired NIC** (wireless does not support this) → right-click → Properties

### 2.1 Power Management tab (all three boxes matter)

✅ **Allow the computer to turn off this device to save power**

✅ **Allow this device to wake the computer** (must be on)

✅ **Only allow a magic packet to wake the computer** (must be on, prevents accidental wake-ups)

### 2.2 Advanced tab

Find the NIC advanced property: **Wake on Magic Packet**

Set it to: **Enabled**

(Names vary slightly by vendor — Intel, Realtek and others all ship an equivalent magic-packet wake switch, and it must be enabled.)

## 3. Windows power settings (the usual reason WOL "doesn't work")

### 3.1 Turn off Fast Startup (most important)

Path: Control Panel → Power Options (left pane) → Choose what the power buttons do → click "Change settings that are currently unavailable" → uncheck **Turn on fast startup (recommended)**

Why: fast startup means Windows is not truly off but hibernated, which kills the NIC standby listener so the magic packet can never wake the host.

### 3.2 Advanced power plan settings

Path: Power Options → Change plan settings → Change advanced power settings

1) Sleep → **Allow hybrid sleep: Off**

2) PCI Express → **Link State Power Management: Off**

Why: stops the OS and the PCIe bus from cutting standby power to the NIC, so the NIC keeps listening after shutdown.

## 4. BIOS settings (most easily overlooked, decides whether waking works at all)

Press Del / F2 / F10 during boot to enter BIOS setup

1. Enable WOL: **Wake On LAN / Power On By PCI-E / PCIE Wakeup = Enabled**

2. Disable power saving: **ErP / EuP / ErP Ready = Disabled**

**Critical: with ErP enabled the machine cuts the NIC's 5V standby power completely at shutdown. The NIC stops working entirely and can never receive a magic packet — WOL fails 100% of the time. ErP must be disabled on every machine you intend to wake remotely.**

Press F10 to save and reboot.

## 5. Hard requirements (all of them, no exceptions)

1. **A wired NIC is mandatory**: almost no wireless NIC supports waking from a powered-off state; only wired NICs have standby power and the listening capability.

2. The PC must **stay plugged in**: do not unplug the power cord or switch off the power strip — the motherboard needs standby power.

3. The Ethernet cable must be seated properly: after shutdown the NIC link LED staying lit means standby mode is working and wake packets can be received.

4. Shut down **from within Windows**: forcing a shutdown with a long power-button press, or cutting power and rebooting, leaves the WOL standby state inconsistent.

5. The waking device (UBNT router) and the Windows host must be on the **same LAN**.
