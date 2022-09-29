package us.donut.mmc;

import java.util.logging.Logger;

public class ServerListPingTest {

    private static final Logger logger = Logger.getLogger(ServerListPingTest.class.getName());

    public static void main(String[] args) throws Exception {
        String serverAddress = args[0];
        int serverPort = Integer.parseInt(args[1]);

        Client client = new Client();
        logger.info("Pinging " + serverAddress + ":" + serverPort);
        InboundPacket packet = client.ping(serverAddress, serverPort);
        if (packet.getPacketID() == 0) {
            logger.info("Status: " + packet.readString());
        } else {
            logger.severe("Unexpected packet: 0x" + Integer.toHexString(packet.getPacketID()));
        }
        client.disconnect();
    }
}
