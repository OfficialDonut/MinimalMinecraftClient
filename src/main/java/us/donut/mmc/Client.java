package us.donut.mmc;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;
import java.util.zip.*;

/**
 * A minimal Minecraft client implementation which provides
 * methods for server list pings, logins, and sending/receiving packets.
 * Packet encryption and compression is handled automatically.
 */
public class Client {

    private static final int PROTOCOL_VERSION = 762;
    private static final String SESSION_URL = "https://sessionserver.mojang.com/session/minecraft/join";
    private static final String SESSION_REQUEST = "{\"accessToken\":\"%s\",\"selectedProfile\":\"%s\",\"serverId\":\"%s\"}";

    private final SecureRandom secureRandom = new SecureRandom();
    private final KeyFactory keyFactory;
    private final KeyGenerator keyGenerator;

    private Socket socket;
    private ClientInputStream inputStream;
    private ClientOutputStream outputStream;
    private final Object outputLock = new Object();

    private int compressionThreshold = -1;

    /**
     * Constructs a new client.
     */
    public Client() {
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128, secureRandom);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void connect(String address, int port) throws IOException {
        disconnect();
        socket = new Socket(address, port);
        inputStream = new ClientInputStream(socket.getInputStream());
        outputStream = new ClientOutputStream(socket.getOutputStream());
    }

    /**
     * Disconnects this client if currently connected to a server.
     * @throws IOException
     */
    public void disconnect() throws IOException {
        if (socket != null) {
            socket.close();
        }
    }

    /**
     * Checks if this client is connected to a server.
     * @return true if the client is connected to a server.
     */
    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }

    /**
     * Sends a packet to the connected server.
     * Packet encryption and compression is handled automatically.
     * This method is thread safe.
     * @param packet the packet to send
     * @throws IOException
     */
    public void send(OutboundPacket packet) throws IOException {
        synchronized (outputLock) {
            if (compressionThreshold >= 0) {
                if (packet.size() < compressionThreshold) {
                    outputStream.writeVarInt(1 + packet.size());
                    outputStream.writeVarInt(0);
                    packet.asBaos().writeTo(outputStream);
                } else {
                    ByteArrayOutputStream compressedPacket = new ByteArrayOutputStream();
                    new ClientOutputStream(compressedPacket).writeVarInt(packet.size());
                    try (DeflaterOutputStream dos = new DeflaterOutputStream(compressedPacket)) {
                        packet.asBaos().writeTo(dos);
                    }
                    outputStream.writeVarInt(compressedPacket.size());
                    compressedPacket.writeTo(outputStream);
                }
            } else {
                outputStream.writeVarInt(packet.size());
                packet.asBaos().writeTo(outputStream);
            }
        }
    }

    /**
     * Reads a packet from the connected server (blocks until a packet is received).
     * Packet encryption and compression is handled automatically.
     * @return the packet from the server
     * @throws IOException
     * @throws DataFormatException
     */
    public InboundPacket receive() throws IOException, DataFormatException {
        int len = inputStream.readVarInt();
        byte[] bytes = new byte[len];
        inputStream.readFully(bytes, 0, len);
        if (compressionThreshold >= 0) {
            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            len = new ClientInputStream(bais).readVarInt();
            if (len > 0) {
                Inflater decompresser = new Inflater();
                decompresser.setInput(bais.readAllBytes());
                decompresser.inflate(bytes = new byte[len]);
                decompresser.end();
            } else {
                bytes = bais.readAllBytes();
            }
        }
        return new InboundPacket(bytes);
    }

    /**
     * Executes a server list ping.
     * @param address the server address (IP or hostname)
     * @param port the server port
     * @return a status response packet if successful
     * @throws IOException
     * @throws DataFormatException
     */
    public InboundPacket ping(String address, int port) throws IOException, DataFormatException {
        connect(address, port);
        handshake(address, port, 1);
        send(new OutboundPacket(0));
        return receive();
    }

    /**
     * Executes the login process.
     * @param account the account with which to login
     * @param address the server address (IP or hostname)
     * @param port the server port
     * @return a login success packet if successful
     * @throws IOException
     * @throws GeneralSecurityException
     * @throws InterruptedException
     * @throws DataFormatException
     */
    public InboundPacket login(Account account, String address, int port) throws IOException, GeneralSecurityException, InterruptedException, DataFormatException {
        connect(address, port);
        handshake(address, port, 2);

        // create and send login start packet
        OutboundPacket loginStartPacket = new OutboundPacket(0);
        loginStartPacket.writeString(account.getUsername());
        loginStartPacket.writeBoolean(account.hasUUID());
        if (account.hasUUID()) {
            loginStartPacket.writeUUID(account.getUUID());
        }
        send(loginStartPacket);

        while (true) {
            InboundPacket packet = receive();
            switch (packet.getPacketID()) {
                case 1: // encryption request
                    encrypt(packet, account);
                    break;
                case 3: // set compression
                    compressionThreshold = packet.readVarInt();
                    break;
                default:
                    return packet;
            }
        }
    }

    private void handshake(String address, int port, int nextState) throws IOException {
        OutboundPacket packet = new OutboundPacket(0);
        packet.writeVarInt(PROTOCOL_VERSION);
        packet.writeString(address);
        packet.writeShort((short) port);
        packet.writeVarInt(nextState);
        send(packet);
    }

    private void encrypt(InboundPacket encryptionRequest, Account account) throws IOException, GeneralSecurityException, InterruptedException {
        // read the encryption request packet
        String serverID = encryptionRequest.readString();
        int pubKeyLen = encryptionRequest.readVarInt();
        byte[] pubKey = new byte[pubKeyLen];
        encryptionRequest.readFully(pubKey, 0, pubKeyLen);
        int tokenLen = encryptionRequest.readVarInt();
        byte[] token = new byte[tokenLen];
        encryptionRequest.readFully(token, 0, tokenLen);

        // generate the shared secret and encrypt it with the server's public key
        SecretKey secret = keyGenerator.generateKey();
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(new X509EncodedKeySpec(pubKey)));
        byte[] encryptedSecret = rsa.doFinal(secret.getEncoded());
        byte[] encryptedToken = rsa.doFinal(token);

        // make session request
        if (account.hasAccessToken() && account.hasUUID()) {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(serverID.getBytes(StandardCharsets.US_ASCII));
            sha1.update(secret.getEncoded());
            sha1.update(pubKey);
            String serverHash = new BigInteger(sha1.digest()).toString(16);

            HttpRequest sessionReq = HttpRequest
                    .newBuilder()
                    .uri(URI.create(SESSION_URL))
                    .POST(HttpRequest.BodyPublishers.ofString(String.format(SESSION_REQUEST, account.getAccessToken(), account.getUUID().toString().replace("-", ""), serverHash)))
                    .build();

            HttpClient.newHttpClient().send(sessionReq, HttpResponse.BodyHandlers.discarding());
        }

        // create and send the encryption response
        OutboundPacket encryptionResponse = new OutboundPacket(1);
        encryptionResponse.writeVarInt(encryptedSecret.length);
        encryptionResponse.write(encryptedSecret);
        encryptionResponse.writeVarInt(encryptedToken.length);
        encryptionResponse.write(encryptedToken);
        send(encryptionResponse);

        // wrap the socket input/output streams with cipher streams to decrypt/encrypt packets
        Cipher aesDecrypt = Cipher.getInstance("AES/CFB8/NoPadding");
        Cipher aesEncrypt = Cipher.getInstance("AES/CFB8/NoPadding");
        aesDecrypt.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(secret.getEncoded()));
        aesEncrypt.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(secret.getEncoded()));
        inputStream = new ClientInputStream(new CipherInputStream(socket.getInputStream(), aesDecrypt));
        outputStream = new ClientOutputStream(new CipherOutputStream(socket.getOutputStream(), aesEncrypt));
    }

    /**
     * Data from a server.
     */
    public static class ClientInputStream extends DataInputStream {

        /**
         * Constructs a new ClientInputStream.
         * @param is the InputStream from which to read
         */
        public ClientInputStream(InputStream is) {
            super(is);
        }

        public int readVarInt() throws IOException {
            int value = 0;
            int position = 0;
            while (true) {
                byte currentByte = readByte();
                value |= (currentByte & 0x7F) << position;
                if ((currentByte & 0x80) == 0) {
                    break;
                }
                position += 7;
                if (position >= 32) {
                    throw new IllegalStateException("VarInt exceeded 5 bytes");
                }
            }
            return value;
        }

        public long readVarLong() throws IOException {
            long value = 0;
            int position = 0;
            while (true) {
                byte currentByte = readByte();
                value |= (long) (currentByte & 0x7F) << position;
                if ((currentByte & 0x80) == 0) {
                    break;
                }
                position += 7;
                if (position >= 64) {
                    throw new IllegalStateException("VarLong exceeded 10 bytes");
                }
            }
            return value;
        }

        public String readString() throws IOException {
            int len = readVarInt();
            byte[] bytes = new byte[len];
            readFully(bytes, 0, len);
            return new String(bytes, StandardCharsets.UTF_8);
        }

        public UUID readUUID() throws IOException {
            return new UUID(readLong(), readLong());
        }
    }

    /**
     * Data going to a server.
     */
    public static class ClientOutputStream extends DataOutputStream {

        /**
         * Constructs a new ClientOutputStream.
         * @param os the OutputStream to write to
         */
        public ClientOutputStream(OutputStream os) {
            super(os);
        }

        public void writeVarInt(int n) throws IOException {
            while (true) {
                if ((n & ~0x7F) == 0) {
                    writeByte(n);
                    return;
                }
                writeByte((n & 0x7F) | 0x80);
                n >>>= 7;
            }
        }

        public void writeVarLong(long n) throws IOException {
            while (true) {
                if ((n & ~0x7F) == 0) {
                    writeByte((int) n);
                    return;
                }
                writeByte((int) (n & 0x7F) | 0x80);
                n >>>= 7;
            }
        }

        public void writeString(String str) throws IOException {
            writeVarInt(str.length());
            write(str.getBytes(StandardCharsets.UTF_8));
        }

        public void writeUUID(UUID uuid) throws IOException {
            writeLong(uuid.getMostSignificantBits());
            writeLong(uuid.getLeastSignificantBits());
        }
    }
}
