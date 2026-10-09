package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.Rule;
import org.junit.Test;

public class JCasCTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void realmIsConfiguredFromYaml() {
        GoogleGroupsSecurityRealm realm =
                (GoogleGroupsSecurityRealm) j.jenkins.getSecurityRealm();
        assertEquals("test-client-id.apps.googleusercontent.com", realm.getClientId());
        assertEquals("s3cret-value", realm.getClientSecret().getPlainText());
        assertEquals("example.com", realm.getHostedDomain());
        assertEquals("^jenkins-.*@example\\.com$", realm.getGroupIncludePattern());
        assertEquals(GroupLookupFailurePolicy.FAIL, realm.getOnGroupLookupFailure());
        assertEquals(3, realm.getGroupAuthorityMaxAgeDays());
        assertFalse(realm.allowsSignup());
    }

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void exportRoundTripsWithoutPlaintextSecret() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ConfigurationAsCode.get().export(out);
        String exported = out.toString(StandardCharsets.UTF_8);
        assertTrue("export should contain the realm symbol", exported.contains("googleGroupsOAuth"));
        assertTrue(exported.contains("hostedDomain: \"example.com\""));
        assertTrue(exported.contains("groupAuthorityMaxAgeDays: 3"));
        assertFalse("client secret must not be exported in plaintext", exported.contains("s3cret-value"));
    }
}
