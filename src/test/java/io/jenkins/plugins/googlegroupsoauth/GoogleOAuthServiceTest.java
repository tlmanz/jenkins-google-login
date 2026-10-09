package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.json.Json;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;

public class GoogleOAuthServiceTest {

    private static final String CLIENT_ID = "client-id.apps.googleusercontent.com";
    private static final String DOMAIN = "example.com";

    private GoogleIdTokenVerifier verifier;
    private GoogleOAuthService service;

    @Before
    public void setUp() {
        verifier = mock(GoogleIdTokenVerifier.class);
        service = new GoogleOAuthService(CLIENT_ID, null, DOMAIN, new MockHttpTransport(), verifier);
    }

    private static GoogleIdToken idToken(GoogleIdToken.Payload payload) {
        JsonWebSignature.Header header = new JsonWebSignature.Header();
        header.setAlgorithm("RS256");
        return new GoogleIdToken(header, payload, new byte[0], new byte[0]);
    }

    private static GoogleIdToken.Payload validPayload() {
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setEmail("Alice@Example.com");
        payload.setEmailVerified(true);
        payload.setHostedDomain("example.com");
        payload.set("name", "Alice Example");
        return payload;
    }

    @Test
    public void validTokenPasses() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleIdToken.Payload payload = service.verifyAndGetPayload(idToken(validPayload()));
        assertEquals("Alice@Example.com", payload.getEmail());
    }

    @Test
    public void hostedDomainIsCaseInsensitive() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleIdToken.Payload payload = validPayload();
        payload.setHostedDomain("Example.COM");
        service.verifyAndGetPayload(idToken(payload));
    }

    @Test
    public void failedSignatureOrIssuerOrAudienceOrExpiryIsRejected() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(false);
        GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
                () -> service.verifyAndGetPayload(idToken(validPayload())));
        assertTrue(e.getMessage().contains("verification"));
    }

    @Test
    public void wrongHostedDomainIsRejected() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleIdToken.Payload payload = validPayload();
        payload.setHostedDomain("evil.com");
        GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
                () -> service.verifyAndGetPayload(idToken(payload)));
        assertTrue(e.getMessage().contains("hd claim"));
    }

    @Test
    public void missingHostedDomainIsRejected() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleIdToken.Payload payload = validPayload();
        payload.setHostedDomain(null);
        assertThrows(GeneralSecurityException.class, () -> service.verifyAndGetPayload(idToken(payload)));
    }

    @Test
    public void unverifiedEmailIsRejected() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleIdToken.Payload payload = validPayload();
        payload.setEmailVerified(false);
        assertThrows(GeneralSecurityException.class, () -> service.verifyAndGetPayload(idToken(payload)));
    }

    @Test
    public void missingEmailIsRejected() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleIdToken.Payload payload = validPayload();
        payload.setEmail(null);
        assertThrows(GeneralSecurityException.class, () -> service.verifyAndGetPayload(idToken(payload)));
    }

    @Test
    public void authorizationUrlContainsExpectedParameters() {
        String url = service.buildAuthorizationUrl("https://jenkins.example.com/securityRealm/finishLogin",
                "the-state", "the-challenge");
        assertTrue(url.startsWith("https://accounts.google.com/o/oauth2/auth")
                || url.startsWith("https://accounts.google.com/o/oauth2/v2/auth"));
        assertTrue(url.contains("client_id=client-id.apps.googleusercontent.com"));
        assertTrue(url.contains("state=the-state"));
        assertTrue(url.contains("code_challenge=the-challenge"));
        assertTrue(url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("hd=example.com"));
        assertTrue(url.contains("cloud-identity.groups.readonly"));
        assertTrue(url.contains("openid"));
    }

    @Test
    public void productionConstructorBuildsWorkingService() {
        GoogleOAuthService svc = new GoogleOAuthService(CLIENT_ID, null, DOMAIN, new MockHttpTransport());
        assertTrue(svc.buildAuthorizationUrl("https://cb.example.com/finish", "s", "c")
                .contains("client_id=" + CLIENT_ID));
    }

    @Test
    public void exchangeCodeSendsCodeVerifierAndParsesTokens() throws Exception {
        MockLowLevelHttpResponse response = new MockLowLevelHttpResponse()
                .setContentType(Json.MEDIA_TYPE)
                .setContent("{\"access_token\":\"the-access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
        MockHttpTransport transport = new MockHttpTransport.Builder()
                .setLowLevelHttpResponse(response)
                .build();
        GoogleOAuthService svc = new GoogleOAuthService(CLIENT_ID, null, DOMAIN, transport, verifier);

        GoogleTokenResponse tokens = svc.exchangeCode("the-code", "https://cb.example.com/finish", "the-verifier");

        assertEquals("the-access-token", tokens.getAccessToken());
        String body = transport.getLowLevelHttpRequest().getContentAsString();
        assertTrue(body.contains("code=the-code"));
        assertTrue(body.contains("code_verifier=the-verifier"));
        assertTrue(body.contains("grant_type=authorization_code"));
    }

    @Test
    public void idTokenIsParsedOutOfTokenResponse() throws Exception {
        when(verifier.verify(any(GoogleIdToken.class))).thenReturn(true);
        GoogleTokenResponse tokenResponse = new GoogleTokenResponse();
        tokenResponse.setIdToken(serializeUnsigned(validPayload()));
        assertEquals("Alice@Example.com", service.verifyAndGetPayload(tokenResponse).getEmail());
    }

    @Test
    public void tokenResponseWithoutIdTokenIsRejected() {
        GoogleTokenResponse tokenResponse = new GoogleTokenResponse();
        assertThrows(GeneralSecurityException.class, () -> service.verifyAndGetPayload(tokenResponse));
    }

    /** JWS-serializes a payload with a dummy signature; the (mocked) verifier never checks it. */
    private static String serializeUnsigned(GoogleIdToken.Payload payload) throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(GsonFactory.getDefaultInstance().toByteArray(payload))
                + "." + b64.encodeToString("sig".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void pkceChallengeIsRfc7636S256() {
        // Test vector from RFC 7636 appendix B
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                GoogleGroupsSecurityRealm.s256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }
}
