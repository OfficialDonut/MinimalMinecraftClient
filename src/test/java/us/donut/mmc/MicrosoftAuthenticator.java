package us.donut.mmc;

import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;

import java.awt.*;
import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class MicrosoftAuthenticator {

    private static final String OAUTH_CODE_URL = "https://login.live.com/oauth20_authorize.srf";
    private static final String OAUTH_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
    private static final String XBL_URL = "https://user.auth.xboxlive.com/user/authenticate";
    private static final String XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
    private static final String MC_AUTH_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
    private static final String MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";
    private static final String MC_CERT_URL = "https://api.minecraftservices.com/player/certificates";

    private static final String OAUTH_CODE_QUERY =
            "?client_id=%s" +
            "&response_type=code" +
            "&response_mode=query" +
            "&scope=" + URLEncoder.encode("XboxLive.signin XboxLive.offline_access", StandardCharsets.UTF_8).replace("%", "%%") +
            "&redirect_uri=" + URLEncoder.encode("http://localhost:8080", StandardCharsets.UTF_8).replace("%", "%%");

    private static final String OAUTH_TOKEN_REQUEST =
            "client_id=%s" +
            "&code=%s" +
            "&grant_type=authorization_code" +
            "&redirect_uri=" + URLEncoder.encode("http://localhost:8080", StandardCharsets.UTF_8).replace("%", "%%");

    private static final String XBL_REQUEST =
            "{" +
            "    \"Properties\": {" +
            "        \"AuthMethod\": \"RPS\"," +
            "        \"SiteName\": \"user.auth.xboxlive.com\"," +
            "        \"RpsTicket\": \"d=%s\"" +
            "    }," +
            "    \"RelyingParty\": \"http://auth.xboxlive.com\"," +
            "    \"TokenType\": \"JWT\"" +
            "}";

    private static final String XSTS_REQUEST =
            "{" +
            "    \"Properties\": {" +
            "        \"SandboxId\": \"RETAIL\"," +
            "        \"UserTokens\": [\"%s\"]" +
            "    }," +
            "    \"RelyingParty\": \"rp://api.minecraftservices.com/\"," +
            "    \"TokenType\": \"JWT\"" +
            "}";

    private static final String MC_REQUEST =
            "{" +
            "    \"identityToken\": \"XBL3.0 x=%s;%s\"" +
            "}";

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final String azureClientID;

    public MicrosoftAuthenticator(String azureClientID) {
        this.azureClientID = azureClientID;
    }

    public Account login() throws IOException, InterruptedException, ExecutionException, TimeoutException, NoSuchAlgorithmException, InvalidKeySpecException {
        String token = fetchAccessToken(fetchAuthToken());
        Account account = fetchProfile(token);
        account.setCertificate(fetchCertificate(token));
        return account;
    }

    private String fetchAuthToken() throws IOException, ExecutionException, InterruptedException, TimeoutException {
        CompletableFuture<String> future = new CompletableFuture<>();

        HttpServer authCodeReceiver = HttpServer.create(new InetSocketAddress(8080), 0);
        authCodeReceiver.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            if (query != null && query.startsWith("code=")) {
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
                exchange.getResponseBody().close();
                future.complete(query.substring(5));
            } else {
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_REQUEST, 0);
            }
            exchange.getResponseBody().close();
        });
        authCodeReceiver.setExecutor(null);
        authCodeReceiver.start();

        try {
            Desktop.getDesktop().browse(URI.create(OAUTH_CODE_URL + String.format(OAUTH_CODE_QUERY, azureClientID)));
            String authCode = future.get(30, TimeUnit.SECONDS);

            HttpRequest tokenReq = HttpRequest
                    .newBuilder()
                    .uri(URI.create(OAUTH_TOKEN_URL))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(String.format(OAUTH_TOKEN_REQUEST, azureClientID, authCode)))
                    .build();

            HttpResponse<String> response = httpClient.send(tokenReq, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != HttpURLConnection.HTTP_OK) {
                throw new IllegalStateException(String.valueOf(response.statusCode()));
            }

            return new JSONObject(response.body()).getString("access_token");
        } finally {
            authCodeReceiver.stop(0);
        }
    }

    private String fetchAccessToken(String authToken) throws IOException, InterruptedException {
        JSONObject xblResp = postJson(XBL_URL, String.format(XBL_REQUEST, authToken));
        JSONObject xstsResp = postJson(XSTS_URL, String.format(XSTS_REQUEST, xblResp.getString("Token")));
        String uhs = xstsResp.getJSONObject("DisplayClaims").getJSONArray("xui").getJSONObject(0).getString("uhs");
        JSONObject mcAuthResp = postJson(MC_AUTH_URL, String.format(MC_REQUEST, uhs, xstsResp.getString("Token")));
        return mcAuthResp.getString("access_token");
    }

    private Account fetchProfile(String token) throws IOException, InterruptedException {
        HttpRequest profileReq = HttpRequest
                .newBuilder()
                .uri(URI.create(MC_PROFILE_URL))
                .header("Authorization", String.format("Bearer %s", token))
                .build();

        HttpResponse<String> response = httpClient.send(profileReq, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != HttpURLConnection.HTTP_OK) {
            throw new IllegalStateException(String.valueOf(response.statusCode()));
        }

        JSONObject json = new JSONObject(response.body());
        Account account = new Account(json.getString("name"));
        account.setUUID(new UUID(Long.parseUnsignedLong(json.getString("id"), 0, 16, 16), Long.parseUnsignedLong(json.getString("id"), 16, 32, 16)));
        account.setAccessToken(token);
        return account;
    }

    private Account.Certificate fetchCertificate(String token) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        HttpRequest profileReq = HttpRequest
                .newBuilder()
                .uri(URI.create(MC_CERT_URL))
                .version(HttpClient.Version.HTTP_1_1)
                .header("Authorization", String.format("Bearer %s", token))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> response = httpClient.send(profileReq, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != HttpURLConnection.HTTP_OK) {
            throw new IllegalStateException(String.valueOf(response.statusCode()));
        }

        JSONObject json = new JSONObject(response.body());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] privateKeyBytes = Base64.getDecoder().decode(json.getJSONObject("keyPair").getString("privateKey").replaceAll("-----.+?-----", "").replace("\n", ""));
        byte[] publicKeyBytes = Base64.getDecoder().decode(json.getJSONObject("keyPair").getString("publicKey").replaceAll("-----.+?-----", "").replace("\n", ""));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        byte[] publicKeySig = Base64.getDecoder().decode(json.getString("publicKeySignatureV2"));
        long expiration = Instant.parse(json.getString("expiresAt")).toEpochMilli();
        return new Account.Certificate(privateKey, publicKey, publicKeySig, expiration);
    }

    private JSONObject postJson(String url, String body) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest
                .newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != HttpURLConnection.HTTP_OK) {
            throw new IllegalStateException(String.valueOf(response.statusCode()));
        }

        return new JSONObject(response.body());
    }
}
