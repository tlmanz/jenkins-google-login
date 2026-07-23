package io.jenkins.plugins.googlegroupsoauth;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;

/**
 * Google OAuth 2.0 code flow: authorization URL construction, code exchange, and ID token
 * verification including the {@code hd} (hosted domain) claim check.
 */
class GoogleOAuthService {

    static final List<String> SCOPES = List.of(
            "openid",
            "email",
            "profile",
            "https://www.googleapis.com/auth/cloud-identity.groups.readonly");

    private final String clientId;
    private final Secret clientSecret;
    private final String hostedDomain;
    private final HttpTransport transport;
    private final JsonFactory jsonFactory = GsonFactory.getDefaultInstance();
    private final GoogleIdTokenVerifier verifier;

    GoogleOAuthService(
            @NonNull String clientId,
            @CheckForNull Secret clientSecret,
            @NonNull String hostedDomain,
            @NonNull HttpTransport transport) {
        this(clientId, clientSecret, hostedDomain, transport,
                new GoogleIdTokenVerifier.Builder(transport, GsonFactory.getDefaultInstance())
                        .setAudience(Collections.singleton(clientId))
                        .build());
    }

    /** Test constructor allowing the signature/issuer/audience verifier to be stubbed. */
    GoogleOAuthService(
            @NonNull String clientId,
            @CheckForNull Secret clientSecret,
            @NonNull String hostedDomain,
            @NonNull HttpTransport transport,
            @NonNull GoogleIdTokenVerifier verifier) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.hostedDomain = hostedDomain;
        this.transport = transport;
        this.verifier = verifier;
    }

    /**
     * Builds the Google authorization endpoint URL with PKCE (S256) and the {@code hd} hint.
     * The {@code hd} parameter is only a UI hint; the authoritative check is
     * {@link #verifyAndGetPayload} on the returned ID token.
     */
    @NonNull
    String buildAuthorizationUrl(@NonNull String redirectUri, @NonNull String state, @NonNull String codeChallenge) {
        GoogleAuthorizationCodeRequestUrl url = new GoogleAuthorizationCodeRequestUrl(clientId, redirectUri, SCOPES);
        url.setState(state);
        url.set("code_challenge", codeChallenge);
        url.set("code_challenge_method", "S256");
        url.set("hd", hostedDomain);
        return url.build();
    }

    @NonNull
    GoogleTokenResponse exchangeCode(@NonNull String code, @NonNull String redirectUri, @NonNull String codeVerifier)
            throws IOException {
        GoogleAuthorizationCodeTokenRequest request = new GoogleAuthorizationCodeTokenRequest(
                transport, jsonFactory, clientId,
                clientSecret != null ? clientSecret.getPlainText() : "",
                code, redirectUri);
        request.set("code_verifier", codeVerifier);
        return request.execute();
    }

    @NonNull
    GoogleIdToken.Payload verifyAndGetPayload(@NonNull GoogleTokenResponse tokenResponse)
            throws IOException, GeneralSecurityException {
        String idTokenString = tokenResponse.getIdToken();
        if (idTokenString == null) {
            throw new GeneralSecurityException("Token response contained no ID token");
        }
        return verifyAndGetPayload(GoogleIdToken.parse(jsonFactory, idTokenString));
    }

    /**
     * Verifies signature, issuer, audience and expiry via {@link GoogleIdTokenVerifier}, then
     * enforces {@code email_verified} and that the {@code hd} claim equals the configured
     * hosted domain (defense in depth on top of the Internal consent screen).
     */
    @NonNull
    GoogleIdToken.Payload verifyAndGetPayload(@NonNull GoogleIdToken idToken)
            throws IOException, GeneralSecurityException {
        if (!verifier.verify(idToken)) {
            throw new GeneralSecurityException(
                    "ID token failed verification (signature/issuer/audience/expiry)");
        }
        GoogleIdToken.Payload payload = idToken.getPayload();
        if (payload.getEmail() == null) {
            throw new GeneralSecurityException("ID token contains no email claim");
        }
        if (!Boolean.TRUE.equals(payload.getEmailVerified())) {
            throw new GeneralSecurityException("Email " + payload.getEmail() + " is not verified by Google");
        }
        String hd = payload.getHostedDomain();
        if (hd == null || !hostedDomain.equalsIgnoreCase(hd)) {
            throw new GeneralSecurityException(
                    "ID token hd claim '" + hd + "' does not match required hosted domain '" + hostedDomain + "'");
        }
        return payload;
    }
}
