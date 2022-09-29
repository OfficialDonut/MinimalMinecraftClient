# Minimal Minecraft Client

A minimal client implementation for Minecraft 1.19.2 ([protocol version 760](https://wiki.vg/Protocol)).

Features:
- [x] Authenticated server login
- [x] Server list pings
- [x] Offline mode servers
- [x] Packet encryption and compression
- [x] Lightweight (no dependencies)

Requires:
- Java 11+

## Usage
[Javadocs](https://officialdonut.github.io/MinimalMinecraftClient)

<details>
<summary>Maven</summary>

```
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```
```
<dependency>
    <groupId>com.github.OfficialDonut</groupId>
    <artifactId>MinimalMinecraftClient</artifactId>
    <version>Tag</version>
</dependency>
```
</details>
<details>
<summary>Gradle</summary>

```
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```
```
dependencies {
    implementation 'com.github.OfficialDonut:MinimalMinecraftClient:Tag'
}
```
</details>

See full examples in [src/test](https://github.com/OfficialDonut/MinimalMinecraftClient/tree/master/src/test/java/us/donut/mmc).

### Keep Alive Packets
```java
Account account = ...
Client client = new Client();
InboundPacket packet = client.login(account, "localhost", 25565);

if (packet.getPacketID() == 2) { // login sucess packet
    while (true) {
        packet = client.receive();
        switch (packet.getPacketID()) {
            case 0x20: // keep alive
                long id = packet.readLong();
                OutboundPacket keepAlivePacket = new OutboundPacket(0x12);
                keepAlivePacket.writeLong(id);
                client.send(keepAlivePacket);
                break;
            case 0x19: // disconnect
                System.out.println("Disconnected: " + packet.readString());
                return;
        }
    }
}
```

#### Server List Ping
```java
Client client = new Client();
InboundPacket packet = client.ping("localhost", 25565);
if (packet.getPacketID() == 0) { // status response
    System.out.println("Status: " + packet.readString());
}
```

## License
This project is licensed under the [MIT License](LICENSE).
