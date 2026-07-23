package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.testing.http.MockHttpTransport;
import java.security.GeneralSecurityException;
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
    public void pkceChallengeIsRfc7636S256() {
        // Test vector from RFC 7636 appendix B
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                GoogleGroupsSecurityRealm.s256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }
}
