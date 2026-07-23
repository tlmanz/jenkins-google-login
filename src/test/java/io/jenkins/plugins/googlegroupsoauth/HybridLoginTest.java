package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import hudson.security.HudsonPrivateSecurityRealm;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlPage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Break-glass behavior: with the Google realm active, a pre-existing local user (created
 * under the local-database realm, as on the real controller) can still log in with username
 * and password through the standard login form, and the login page carries the
 * "Sign in with Google" button.
 */
public class HybridLoginTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void setUp() throws Exception {
        // Simulate the migration: users exist from the local-database era...
        HudsonPrivateSecurityRealm localRealm = new HudsonPrivateSecurityRealm(false, false, null);
        j.jenkins.setSecurityRealm(localRealm);
        localRealm.createAccount("qaautomation", "hunter2");
        // ...then the realm is switched to Google OAuth.
        j.jenkins.setSecurityRealm(new GoogleGroupsSecurityRealm(
                "client-id", null, "example.com"));
    }

    @Test
    public void localPasswordLoginStillWorks() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("qaautomation", "hunter2");
        assertEquals("qaautomation", wc.executeOnServer(
                () -> jenkins.model.Jenkins.getAuthentication2().getName()));
    }

    @Test
    public void wrongPasswordIsRejected() {
        JenkinsRule.WebClient wc = j.createWebClient();
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("qaautomation", "wrong"));
    }

    @Test
    public void unknownUserIsRejected() {
        JenkinsRule.WebClient wc = j.createWebClient();
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("nobody", "whatever"));
    }

    @Test
    public void loginPageShowsFormAndGoogleButton() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        HtmlPage login = wc.goTo("login");
        String content = login.getWebResponse().getContentAsString();
        assertTrue("username/password form should be present", content.contains("j_username"));
        assertTrue("Google sign-in button should be present",
                content.contains("securityRealm/commenceLogin"));
    }

    @Test
    public void apiTokenOfLocalUserStillAuthenticates() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("qaautomation", "hunter2");
        String token = wc.executeOnServer(() -> hudson.model.User.getById("qaautomation", false)
                .getProperty(jenkins.security.ApiTokenProperty.class)
                .generateNewToken("test").plainValue);
        JenkinsRule.WebClient anonymous = j.createWebClient();
        anonymous.withBasicCredentials("qaautomation", token);
        assertTrue(anonymous.goTo("whoAmI/api/json", "application/json")
                .getWebResponse().getContentAsString().contains("\"qaautomation\""));
    }
}
