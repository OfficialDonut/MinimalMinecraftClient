package us.donut.mmc;

import java.util.logging.Logger;

public class KeepAliveTest {

    private static final Logger logger = Logger.getLogger(KeepAliveTest.class.getName());

    public static void main(String[] args) throws Exception {
        String azureClientID = args[0];
        String serverAddress = args[1];
        int serverPort = Integer.parseInt(args[2]);

        logger.info("Authenticating with " + azureClientID);
        MicrosoftAuthenticator authenticator = new MicrosoftAuthenticator(azureClientID);
        Account account = authenticator.login();
        logger.info(account.toString());

        Client client = new Client();
        logger.info("Logging into " + serverAddress + ":" + serverPort);
        InboundPacket packet = client.login(account, serverAddress, serverPort);

        if (packet.getPacketID() == 2) {
            logger.info("Received login success.");
            while (true) {
                packet = client.receive();
                switch (packet.getPacketID()) {
                    case 0x23: // keep alive
                        long id = packet.readLong();
                        logger.info("Received keep alive " + id);
                        OutboundPacket keepAlivePacket = new OutboundPacket(0x12);
                        keepAlivePacket.writeLong(id);
                        client.send(keepAlivePacket);
                        logger.info("Sent keep alive " + id);
                        break;
                    case 0x19: // disconnect
                        logger.severe("Disconnected: " + packet.readString());
                        return;
                    default:
                        logger.fine("Ignoring packet: 0x" + Integer.toHexString(packet.getPacketID()));
                        break;
                }
            }
        } else if (packet.getPacketID() == 0) {
            logger.severe("Disconnected: " + packet.readString());
        } else {
            logger.severe("Unexpected packet: 0x" + Integer.toHexString(packet.getPacketID()));
        }
    }
}
