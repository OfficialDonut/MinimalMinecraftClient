package us.donut.mmc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Represents a packet going to a server.
 */
public class OutboundPacket extends Client.ClientOutputStream {

    private final int packetID;

    /**
     * Constructs a new OutboundPacket with the given packet ID.
     * @param packetID the packet ID
     * @throws IOException
     */
    public OutboundPacket(int packetID) throws IOException {
        super(new ByteArrayOutputStream());
        writeVarInt(this.packetID = packetID);
    }

    protected ByteArrayOutputStream asBaos() {
        return (ByteArrayOutputStream) out;
    }

    public int getPacketID() {
        return packetID;
    }
}
