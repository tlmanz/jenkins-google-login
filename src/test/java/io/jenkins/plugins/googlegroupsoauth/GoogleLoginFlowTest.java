package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import jenkins.model.JenkinsLocationConfiguration;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Drives the OAuth code flow over HTTP against a real Jenkins: only the Google token
 * exchange and ID token verification are stubbed (via the {@code createOAuthService} seam);
 * state/PKCE handling, session fixation, redirects and error paths run for real.
 */
@WithJenkins
public class GoogleLoginFlowTest {

    private static final String EMAIL = "alice@example.com";
    private static final String GROUP = "jenkins-qa@example.com";

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    /** Realm whose OAuth service never touches the network and yields a fixed identity. */
    private static class TestRealm extends GoogleGroupsSecurityRealm {
        transient IOException nextExchangeFailure;
        transient String subject = "sub-alice";

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
                    payload.setSubject(subject);
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

        // provider-reported error: a well-formed OAuth error code is shown...
        Page denied = get(rawClient(), "securityRealm/finishLogin?error=access_denied");
        assertEquals(401, denied.getWebResponse().getStatusCode());
        assertTrue(denied.getWebResponse().getContentAsString().contains("access_denied"));

        // ...but arbitrary attacker-chosen text is not echoed into the page
        Page spoofed = get(rawClient(), "securityRealm/finishLogin?error="
                + URLEncoder.encode("Call 555-0100 to restore access", StandardCharsets.UTF_8));
        assertEquals(401, spoofed.getWebResponse().getStatusCode());
        assertFalse(spoofed.getWebResponse().getContentAsString().contains("555-0100"));

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
    public void emailReassignedToAnotherGoogleAccountIsRefused() throws Exception {
        TestRealm realm = new TestRealm();
        j.jenkins.setSecurityRealm(realm);

        JenkinsRule.WebClient wc = rawClient();
        assertEquals(302, finishLogin(wc, commenceAndGetState(wc, "")).getWebResponse().getStatusCode());
        assertEquals("sub-alice", User.getById(EMAIL, false).getProperty(GoogleAccountProperty.class).getSubject());

        // Same email, different Google account: refused, binding unchanged, no session.
        realm.subject = "sub-someone-else";
        JenkinsRule.WebClient wc2 = rawClient();
        assertEquals(401, finishLogin(wc2, commenceAndGetState(wc2, "")).getWebResponse().getStatusCode());
        assertTrue(get(wc2, "securityRealm/whoami/").getWebResponse().getContentAsString().contains("not logged in"));
        assertEquals("sub-alice", User.getById(EMAIL, false).getProperty(GoogleAccountProperty.class).getSubject());

        // The original account still gets in.
        realm.subject = "sub-alice";
        JenkinsRule.WebClient wc3 = rawClient();
        assertEquals(302, finishLogin(wc3, commenceAndGetState(wc3, "")).getWebResponse().getStatusCode());
    }

    @Test
    public void groupAuthoritiesForApiTokensExpireAfterMaxAge() throws Exception {
        TestRealm realm = new TestRealm();
        AtomicLong now = new AtomicLong(TimeUnit.DAYS.toMillis(1000));
        realm.setClock(now::get);
        j.jenkins.setSecurityRealm(realm);
        assertEquals(7, realm.getGroupAuthorityMaxAgeDays());

        JenkinsRule.WebClient wc = rawClient();
        finishLogin(wc, commenceAndGetState(wc, ""));
        User.getById("local-bot", true); // a non-Google user record, e.g. from the local-database era

        now.addAndGet(TimeUnit.DAYS.toMillis(7));
        assertTrue(hasAuthority(realm.loadUserByUsername2(EMAIL), GROUP), "still within max age");

        now.addAndGet(1);
        UserDetails expired = realm.loadUserByUsername2(EMAIL);
        assertFalse(hasAuthority(expired, GROUP), "group authority must expire");
        assertTrue(hasAuthority(expired, "authenticated"));
        assertTrue(hasAuthority(realm.loadUserByUsername2("local-bot"), "authenticated"),
                "non-Google users never expire");

        realm.setGroupAuthorityMaxAgeDays(0);
        assertTrue(hasAuthority(realm.loadUserByUsername2(EMAIL), GROUP), "0 disables expiry");

        // A fresh Google login renews the authorities.
        realm.setGroupAuthorityMaxAgeDays(7);
        JenkinsRule.WebClient wc2 = rawClient();
        finishLogin(wc2, commenceAndGetState(wc2, ""));
        assertTrue(hasAuthority(realm.loadUserByUsername2(EMAIL), GROUP));
    }

    @Test
    public void incompleteConfigurationFailsLoginClearly() throws Exception {
        j.jenkins.setSecurityRealm(new GoogleGroupsSecurityRealm("", null, "example.com"));
        assertMisconfigured("Client ID");

        j.jenkins.setSecurityRealm(new GoogleGroupsSecurityRealm("client-id", null, " "));
        assertMisconfigured("hosted domain");

        // No configured Jenkins URL: the Host header must not be used to build the redirect URI.
        j.jenkins.setSecurityRealm(new TestRealm());
        JenkinsLocationConfiguration.get().setUrl(null);
        assertMisconfigured("Jenkins URL");
        assertEquals(500, get(rawClient(), "securityRealm/finishLogin?code=x&state=y")
                .getWebResponse().getStatusCode());
    }

    private void assertMisconfigured(String expected) throws IOException {
        Page page = get(rawClient(), "securityRealm/commenceLogin");
        assertEquals(500, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains(expected));
    }

    private static boolean hasAuthority(UserDetails details, String authority) {
        return details.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch(authority::equals);
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

        assertEquals(FormValidation.Kind.OK, d.doCheckGroupAuthorityMaxAgeDays("7").kind);
        assertEquals(FormValidation.Kind.WARNING, d.doCheckGroupAuthorityMaxAgeDays("0").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckGroupAuthorityMaxAgeDays("-1").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckGroupAuthorityMaxAgeDays("seven").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckGroupAuthorityMaxAgeDays("").kind);

        ListBoxModel model = d.doFillOnGroupLookupFailureItems();
        assertEquals(2, model.size());
    }
}
