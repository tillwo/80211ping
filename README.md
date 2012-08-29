80211ping
=========

What is it?
-----------

80211ping is a small Linux command-line tool to "ping" 802.11 stations (e.g. any WiFi device).


What can it be used for?
------------------------

* To test for the presence of a particular WiFi device.
* To prevent power save mode of a particular device device (try the -m option.)
* To test the link quality (by sending "pings" with at different data rates.)

The most important advantage over a normal "ping" is that 80211ping works on the link layer. Hence, you don't need to be associated to the same wireless network as the target, in fact, both devices don't need to be associated at all. Firewalls blocking ICMP, wrong IP addresses etc. do not matter since they are all on network layer.


How to use?
-----------

### In general
    80211ping 0.1
    Usage:
     80211ping <options> <destination>
      -I <device>    device to use (mandatory, device must be in monitor mode)
      -c <count>     stop after sending <count> packets (default: don't stop)
      -i <interval>  send packet each <interval> ms (default: 1000 ms)
      -r <rate>      specify data rate (in Mbit/s, not supported by all drivers)
      -m             set "more data" flag

### Example
    $ sudo ./80211ping -I mon0 -c 10 XX:XX:XX:XX:XX:XX
    Sending null data frames from AE:24:BC:89:AF:9F to XX:XX:XX:XX:XX:XX every 1.00s...
    Sending frame to XX:XX:XX:XX:XX:XX: reply received! (1 duplicate ACKs)
    Sending frame to XX:XX:XX:XX:XX:XX: reply received!
    Sending frame to XX:XX:XX:XX:XX:XX: reply received! (2 duplicate ACKs)
    Sending frame to XX:XX:XX:XX:XX:XX: no reply.
    Sending frame to XX:XX:XX:XX:XX:XX: reply received! (4 duplicate ACKs)
    Sending frame to XX:XX:XX:XX:XX:XX: reply received! (1 duplicate ACKs)
    Sending frame to XX:XX:XX:XX:XX:XX: no reply.
    Sending frame to XX:XX:XX:XX:XX:XX: no reply.
    Sending frame to XX:XX:XX:XX:XX:XX: no reply.
    Sending frame to XX:XX:XX:XX:XX:XX: reply received!
    10 packets sent, 6 packets acknowledged (60.0%)

80211ping needs a network device in monitor mode that uses Radiotap headers. So far I tested 80211ping with MadWiFi and iwlwifi, but any mac80211 based wireless LAN driver should work as long as it does support frame injection. To use 80211ping, you can create a monitor mode device in parallel to another device.

### For iwlwifi (or other mac80211 based drivers):
    # iw dev wlan0 interface add mon0 type monitor
    # ifconfig mon0 up
    # ./80211ping -I mon0 xx:xx:xx:xx:xx:xx

### For MadWiFi:
    # wlanconfig ath0 create wlandev wifi0 wlanmode monitor
    # ifconfig ath0 up
    # ./80211ping -I ath0 xx:xx:xx:xx:xx:xx

### Notes:
* Not all drivers support setting the data rate.
* The "ping" frames will only reach the target device when both sending and target device are set to the same channel.
* When creating a monitor mode device in parallel to another (client or AP) device, the channel of the monitor mode device may be determined by the other device.


How does it work?
-----------------

80211ping sends a 802.11 null data frames addressed to the target device and then waits for acknowledgement (ACK) frames. This works because all 802.11 devices I met so far acknowledge every valid frame they receive that is addressed to them and has a correct FCS. 80211ping uses a randomly selected MAC address as source and BSSID address. Libpcap is used for both injection and capturing.


How to compile?
---------------

For compiling 80211ping you only need GCC and standard binutils plus libpcap and its header files. A makefile is provided.

80211ping can be built using the OpenWRT toolchain (tested with backfire):

    $ export STAGING_DIR=/path/to/openwrt/backfire/staging_dir
    $ export PATH=$PATH:STAGING_DIR/toolchain-mips_r2_gcc-4.3.3+cs_uClibc-0.9.30.1/bin
    $ make CC=mips-openwrt-linux-gcc CFLAGS="-I$STAGING_DIR/target-mips_r2_uClibc-0.9.30.1/usr/include" LFLAGS="-L$STAGING_DIR/target-mips_r2_uClibc-0.9.30.1/usr/lib"


Questions?
----------

You can reach me through till &lt;dot&gt; wollenberg &lt;at&gt; uni-rostock &lt;dot&gt; de. Bug reports are welcome. :-)

