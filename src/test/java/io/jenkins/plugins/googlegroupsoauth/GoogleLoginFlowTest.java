package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.testing.http.MockHttpTransport;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Drives the OAuth code flow over HTTP against a real Jenkins: only the Google token
 * exchange and ID token verification are stubbed (via the {@code createOAuthService} seam);
 * state/PKCE handling, session fixation, redirects and error paths run for real.
 */
public class GoogleLoginFlowTest {

    private static final String EMAIL = "alice@example.com";
    private static final String GROUP = "jenkins-qa@example.com";

    @Rule
    public JenkinsRule j = new JenkinsRule();

    /** Realm whose OAuth service never touches the network and yields a fixed identity. */
    private static class TestRealm extends GoogleGroupsSecurityRealm {
        transient IOException nextExchangeFailure;

        TestRealm() {
            super("client-id", null, "example.com");
            setGroupResolver((email, token) -> List.of(GROUP));
        }

        @Override
        GoogleOAuthService createOAuthService() {
            return new GoogleOAuthService("client-id", null, "example.com", new MockHttpTransport()) {
                @Override
                GoogleTokenResponse exchangeCode(String code, String redirectUri, String codeVerifier)
                        throws IOException {
                    if (nextExchangeFailure != null) {
                        IOException failure = nextExchangeFailure;
                        nextExchangeFailure = null;
                        throw failure;
                    }
                    GoogleTokenResponse response = new GoogleTokenResponse();
                    response.setAccessToken("access-token");
                    return response;
                }

                @Override
                GoogleIdToken.Payload verifyAndGetPayload(GoogleTokenResponse tokenResponse) {
                    GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
                    payload.setEmail("Alice@Example.com");
                    payload.setEmailVerified(true);
                    payload.setHostedDomain("example.com");
                    payload.set("name", "Alice Example");
                    return payload;
                }
            };
        }
    }

    private JenkinsRule.WebClient rawClient() {
        JenkinsRule.WebClient wc = j.createWebClient();
        wc.getOptions().setRedirectEnabled(false);
        wc.getOptions().setThrowExceptionOnFailingStatusCode(false);
        return wc;
    }

    private Page get(JenkinsRule.WebClient wc, String relative) throws IOException {
        return wc.getPage(new WebRequest(new URL(j.getURL(), relative)));
    }

    private String commenceAndGetState(JenkinsRule.WebClient wc, String query) throws IOException {
        Page page = get(wc, "securityRealm/commenceLogin" + query);
        assertEquals(302, page.getWebResponse().getStatusCode());
        String state = queryParam(page.getWebResponse().getResponseHeaderValue("Location"), "state");
        assertNotNull(state);
        return state;
    }

    private Page finishLogin(JenkinsRule.WebClient wc, String state) throws IOException {
        return get(wc, "securityRealm/finishLogin?code=auth-code&state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8));
    }

    private static String queryParam(String url, String name) {
        for (String kv : url.substring(url.indexOf('?') + 1).split("&")) {
            String[] pair = kv.split("=", 2);
            if (pair[0].equals(name)) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    @Test
    public void commenceLoginRedirectsToGoogleWithPkceStateAndHd() throws Exception {
        j.jenkins.setSecurityRealm(new TestRealm());
        Page page = get(rawClient(), "securityRealm/commenceLogin");
        assertEquals(302, page.getWebResponse().getStatusCode());
        String location = page.getWebResponse().getResponseHeaderValue("Location");
        assertTrue(location.startsWith("https://accounts.google.com/"));
        assertTrue(location.contains("client_id=client-id"));
        assertTrue(location.contains("code_challenge="));
        assertTrue(location.contains("code_challenge_method=S256"));
        assertTrue(location.contains("hd=example.com"));
        assertTrue(location.contains("finishLogin"));
        assertTrue(location.contains("cloud-identity.groups.readonly"));
        assertNotNull(queryParam(location, "state"));
    }

    @Test
    public void successfulLoginEstablishesSessionUserRecordAndAuthorities() throws Exception {
        TestRealm realm = new TestRealm();
        j.jenkins.setSecurityRealm(realm);
        JenkinsRule.WebClient wc = rawClient();

        String state = commenceAndGetState(wc, "");
        Page finish = finishLogin(wc, state);
        assertEquals(302, finish.getWebResponse().getStatusCode());
        assertEquals(j.getURL().toString(), finish.getWebResponse().getResponseHeaderValue("Location"));

        String whoami = get(wc, "securityRealm/whoami/").getWebResponse().getContentAsString();
        assertTrue(whoami.contains(EMAIL));
        assertTrue(whoami.contains(GROUP));
        assertTrue(whoami.contains("authenticated"));

        User user = User.getById(EMAIL, false);
        assertNotNull(user);
        assertEquals("Alice Example", user.getFullName());
        assertEquals(EMAIL, user.getProperty(Mailer.UserProperty.class).getAddress());

        // Authorities recorded at login are what API-token/password auth will see later.
        UserDetails details = realm.loadUserByUsername2(EMAIL);
        assertTrue(details.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(GROUP::equals));

        // The callback is single-use: the pre-login session was invalidated.
        assertEquals(401, finishLogin(wc, state).getWebResponse().getStatusCode());
    }

    @Test
    public void invalidCallbacksAreRejected() throws Exception {
        j.jenkins.setSecurityRealm(new TestRealm());

        // provider-reported error
        assertEquals(401, get(rawClient(), "securityRealm/finishLogin?error=access_denied")
                .getWebResponse().getStatusCode());

        // no login session at all
        assertEquals(401, get(rawClient(), "securityRealm/finishLogin?code=x&state=y")
                .getWebResponse().getStatusCode());

        // state mismatch
        JenkinsRule.WebClient wc = rawClient();
        commenceAndGetState(wc, "");
        assertEquals(401, finishLogin(wc, "wrong-state").getWebResponse().getStatusCode());

        // missing code
        JenkinsRule.WebClient wc2 = rawClient();
        String state = commenceAndGetState(wc2, "");
        assertEquals(401, get(wc2, "securityRealm/finishLogin?state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8)).getWebResponse().getStatusCode());
    }

    @Test
    public void stateIsSingleUseAfterFailedTokenExchange() throws Exception {
        TestRealm realm = new TestRealm();
        j.jenkins.setSecurityRealm(realm);
        JenkinsRule.WebClient wc = rawClient();

        String state = commenceAndGetState(wc, "");
        realm.nextExchangeFailure = new IOException("token endpoint down");
        assertEquals(401, finishLogin(wc, state).getWebResponse().getStatusCode());

        // The exchange would succeed now, but the state was consumed by the failed attempt.
        assertEquals(401, finishLogin(wc, state).getWebResponse().getStatusCode());
    }

    @Test
    public void failPolicyRefusesLoginWhenGroupLookupFails() throws Exception {
        TestRealm realm = new TestRealm();
        realm.setOnGroupLookupFailure(GroupLookupFailurePolicy.FAIL);
        realm.setGroupResolver((email, token) -> {
            throw new IOException("lookup down");
        });
        j.jenkins.setSecurityRealm(realm);
        JenkinsRule.WebClient wc = rawClient();

        String state = commenceAndGetState(wc, "");
        assertEquals(401, finishLogin(wc, state).getWebResponse().getStatusCode());
        assertTrue(get(wc, "securityRealm/whoami/").getWebResponse().getContentAsString()
                .contains("not logged in"));
    }

    @Test
    public void redirectAfterLoginHonorsSafeTargetsOnly() throws Exception {
        j.jenkins.setSecurityRealm(new TestRealm());
        String root = j.getURL().toString();

        // safe relative target is honored
        JenkinsRule.WebClient wc = rawClient();
        String state = commenceAndGetState(wc,
                "?from=" + URLEncoder.encode("/whoAmI/", StandardCharsets.UTF_8));
        assertTrue(finishLogin(wc, state).getWebResponse()
                .getResponseHeaderValue("Location").endsWith("/whoAmI/"));

        // off-site target falls back to the Jenkins root
        JenkinsRule.WebClient wc2 = rawClient();
        String state2 = commenceAndGetState(wc2,
                "?from=" + URLEncoder.encode("http://evil.example.com/", StandardCharsets.UTF_8));
        assertEquals(root, finishLogin(wc2, state2).getWebResponse().getResponseHeaderValue("Location"));

        // never bounce back to the login page
        JenkinsRule.WebClient wc3 = rawClient();
        String state3 = commenceAndGetState(wc3,
                "?from=" + URLEncoder.encode("/login", StandardCharsets.UTF_8));
        assertEquals(root, finishLogin(wc3, state3).getWebResponse().getResponseHeaderValue("Location"));

        // same-origin Referer is used when from is absent
        JenkinsRule.WebClient wc4 = rawClient();
        WebRequest commence = new WebRequest(new URL(j.getURL(), "securityRealm/commenceLogin"));
        commence.setAdditionalHeader("Referer", root + "computer/");
        Page page = wc4.getPage(commence);
        String state4 = queryParam(page.getWebResponse().getResponseHeaderValue("Location"), "state");
        assertEquals(root + "computer/",
                finishLogin(wc4, state4).getWebResponse().getResponseHeaderValue("Location"));
    }

    @Test
    public void descriptorValidationAndUnknownUserLookup() {
        GoogleGroupsSecurityRealm realm = new GoogleGroupsSecurityRealm("client-id", null, "example.com");
        j.jenkins.setSecurityRealm(realm);
        assertThrows(UsernameNotFoundException.class, () -> realm.loadUserByUsername2("ghost@example.com"));

        GoogleGroupsSecurityRealm.DescriptorImpl d = (GoogleGroupsSecurityRealm.DescriptorImpl)
                j.jenkins.getDescriptorOrDie(GoogleGroupsSecurityRealm.class);
        assertNotNull(d.getDisplayName());

        assertEquals(FormValidation.Kind.ERROR, d.doCheckClientId("").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckClientId("client-id").kind);

        assertEquals(FormValidation.Kind.ERROR, d.doCheckHostedDomain("").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHostedDomain("user@example.com").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHostedDomain("example.com/path").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHostedDomain("nodot").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckHostedDomain("example.com").kind);

        assertEquals(FormValidation.Kind.OK, d.doCheckGroupIncludePattern("").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckGroupIncludePattern("^jenkins-.*$").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckGroupIncludePattern("[unclosed").kind);

        ListBoxModel model = d.doFillOnGroupLookupFailureItems();
        assertEquals(2, model.size());
    }
}
