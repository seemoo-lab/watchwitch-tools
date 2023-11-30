# watchwitch-tools

A set of scripts and tools for investigating and debugging Apple Watch communication. Part of the collection of Apple Watch related tooling, including [WatchWitch Android](https://github.com/rec0de/watchwitch-android), [WatchWitch iOS Tweak](https://github.com/rec0de/watchwitch-ios) and [WatchWitch iOS Companion](https://github.com/rec0de/watchwitch-ios-companion).

## Traffic Logger

[trafficlogger/trafficlogger.py](trafficlogger/trafficlogger.py)

A python tool combining IKEv2 logging and bluetooth logging to decrypt as much of the communication as possible. Currently performs decryption of ESP payloads as well as detection and parsing of various underlying protocols (ACL, L2CAP, NRLP, ESP).  

Can optionally dump decrypted ESP payloads to `pcap` files for analysis with wireshark or other tools. In this case, payloads will be encapsulated in 'imaginary' Ethernet and IP packets for tool compatibility. Ethernet MAC addresses are set to zero, IP addresses are `127.0.1.*` for the phone (where the trafficlogger is running) and `127.0.2.*` for the watch, where `*` will be the type of the NRLP packet the ESP payload was carried in.

Usage:

`python trafficlogger.py`

`python trafficlogger.py --dump capture` will create pcap files for each cryptographic context named `capture_[context id].pcap`

Sample Output:

The output indicates the packet direction (send/receive) as well as the detected protocol stack. For NRLP, the parameters given are the sequence number and the packet type. For IKEv2, parameters are the initiator cookie and the sequence number. For ESP, parameters are the SPI, the sequence number, and the next header value (usually 6 for TCP).

```
rcv NRLP(#1, t=0x04)->IKEv2(91a56c84, #0) 2200...
snd NRLP(#18, t=0x64)->ESP(099a132f, #51, 6) c070...
rcv NRLP(#30, t=0x03) 7233...
```

## Frida Scripts

### logIKEv2.js

[frida-scripts/logIKEv2.js](frida-scripts/logIKEv2.js)

A collection of frida hooks for `terminusd` to capture and investigate IKEv2 handshakes over bluetooth. Provides packet decryption as well as some parsing and analysis.  

Usage:

`frida -U terminusd -l logIKEv2.js`

### logAlloy.js

[frida-scripts/logAlloy.js](frida-scripts/logAlloy.js)

A collection of frida hooks for `identityservicesd` to capture Alloy traffic. Optionally includes decryptions of A-over-C protected messages. Designed to be used with the Alloy parser for further investigation.  

Note: To capture topics for all messages (which is very helpful!), turn the watch off before starting the script and restart it while already capturing.

Usage:

`frida -U identityservicesd -l logAlloy.js`

### extractKeys.js

[frida-scripts/extractKeys.js](frida-scripts/extractKeys.js)

Hooks into the `cced25519_sign` method to print long-term Ed25519 keys used to authenticate IKEv2 handshakes. See [IKEv2.md](IKEv2.md) for context.

Usage:

`frida -U terminusd -l extractKeys.js`

### notify-inject-PoC.js

[frida-scripts/notify-inject-PoC.js](frida-scripts/notify-inject-PoC.js)

Exploits an oversight in IKEv2 notify payload parsing to inject unencrypted, unauthenticated private notify payloads into an otherwise genuine IKEv2 session to trick the watch into associating an arbitrary IP with the paired iPhone.

Available payloads include a `LinkDirectorMessage` that overwrites the local WiFi IP address the watch associates with the phone and a `ProxyNotify` payload that changes the local port of the SHOES proxy server. The latter payload *should* work but *doesn't* for unknown reasons. We still include it for illustrative purposes.

Usage:

`frida -U bluetoothd -l notifyInjectPoC.js`

## Alloy Parser

The Alloy parser is a subset of the WatchWitch Android source code repackaged to allow analyzing Alloy logs on a computer. It is designed to read the logfiles produced by the `logAlloy.js` frida script and will automatically detect A-over-C plaintexts and keys included in these logs and provide decryption for the corresponding messages.

Usage:

```
cd alloy-parser

# basic usage, parse and log all messages
./gradlew run --args=example.log

# log only messages for specified topics
./gradlew run --args="--include=com.apple.topicA,com.apple.topicB example.log"

# log all messages except specified topics
./gradlew run --args="--exclude=com.apple.topicA,com.apple.topicB example.log"
```
