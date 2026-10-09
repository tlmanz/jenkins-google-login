package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

@WithJenkinsConfiguredWithCode
public class JCasCTest {

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void realmIsConfiguredFromYaml(JenkinsConfiguredWithCodeRule j) {
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
    public void exportRoundTripsWithoutPlaintextSecret(JenkinsConfiguredWithCodeRule j) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ConfigurationAsCode.get().export(out);
        String exported = out.toString(StandardCharsets.UTF_8);
        assertTrue(exported.contains("googleGroupsOAuth"), "export should contain the realm symbol");
        assertTrue(exported.contains("hostedDomain: \"example.com\""));
        assertTrue(exported.contains("groupAuthorityMaxAgeDays: 3"));
        assertFalse(exported.contains("s3cret-value"), "client secret must not be exported in plaintext");
    }
}
