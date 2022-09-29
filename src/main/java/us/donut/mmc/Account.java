package us.donut.mmc;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a Minecraft account.
 * The account UUID, access token, and certificate are optional.
 */
public class Account {

    private String username;
    private UUID uuid;
    private String accessToken;
    private Certificate certificate;

    /**
     * Constructs a new account with the given username.
     * @param username the username
     */
    public Account(String username) {
        this.username = username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public boolean hasUUID() {
        return uuid != null;
    }

    public boolean hasAccessToken() {
        return accessToken != null;
    }

    public boolean hasCertificate() {
        return certificate != null;
    }

    public String getUsername() {
        return username;
    }

    public UUID getUUID() {
        return uuid;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Account account = (Account) o;

        if (!Objects.equals(username, account.username)) return false;
        if (!Objects.equals(uuid, account.uuid)) return false;
        if (!Objects.equals(accessToken, account.accessToken)) return false;
        return Objects.equals(certificate, account.certificate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, uuid, accessToken, certificate);
    }

    @Override
    public String toString() {
        return "Account{" +
                "username='" + username + '\'' +
                ", uuid=" + uuid +
                ", accessToken='" + accessToken + '\'' +
                ", certificate=" + certificate +
                '}';
    }

    /**
     * Represents a player certificate which consists of the Mojang provided key-pair
     * used for cryptographically signing chat messages.
     */
    public static class Certificate {

        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final byte[] publicKeySig;
        private final long expiration;

        /**
         * Constructs a new certificate object with the given fields.
         * @param privateKey the private key
         * @param publicKey the public key
         * @param publicKeySig the public key signature
         * @param expiration the expiration date (millis)
         */
        public Certificate(PrivateKey privateKey, PublicKey publicKey, byte[] publicKeySig, long expiration) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.publicKeySig = publicKeySig;
            this.expiration = expiration;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public byte[] getPublicKeySig() {
            return publicKeySig;
        }

        public long getExpiration() {
            return expiration;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Certificate certificate = (Certificate) o;

            if (expiration != certificate.expiration) return false;
            if (!Objects.equals(privateKey, certificate.privateKey)) return false;
            if (!Objects.equals(publicKey, certificate.publicKey)) return false;
            return Arrays.equals(publicKeySig, certificate.publicKeySig);
        }

        @Override
        public int hashCode() {
            return Objects.hash(privateKey, publicKey, Arrays.hashCode(publicKeySig), expiration);
        }
    }
}
