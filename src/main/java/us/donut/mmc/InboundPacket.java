package us.donut.mmc;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Represents a packet coming from a server.
 */
public class InboundPacket extends Client.ClientInputStream {

    private final int packetID;

    protected InboundPacket(byte[] bytes) throws IOException {
        super(new ByteArrayInputStream(bytes));
        packetID = readVarInt();
    }

    public int getPacketID() {
        return packetID;
    }
}
