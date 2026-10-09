package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/** Realm behavior that needs no running Jenkins. */
public class GoogleGroupsSecurityRealmTest {

    private static GoogleGroupsSecurityRealm realm() {
        return new GoogleGroupsSecurityRealm("client-id", null, "example.com");
    }

    @Test
    public void wellFormedGroupEmailIsAcceptedAndLowercased() {
        assertEquals("jenkins-qa@example.com",
                realm().loadGroupByGroupname2("Jenkins-QA@Example.COM", false).getName());
    }

    @Test
    public void malformedGroupNamesAreRejected() {
        GoogleGroupsSecurityRealm realm = realm();
        assertThrows(UsernameNotFoundException.class, () -> realm.loadGroupByGroupname2("qa-team", false));
        assertThrows(UsernameNotFoundException.class, () -> realm.loadGroupByGroupname2("a@b", false));
        assertThrows(UsernameNotFoundException.class, () -> realm.loadGroupByGroupname2(null, false));
    }

    @Test
    public void logValuesCannotInjectLines() {
        assertEquals("alice_[INFO] forged", GoogleGroupsSecurityRealm.sanitizeForLog("alice\n[INFO] forged"));
        assertEquals("a_b_c", GoogleGroupsSecurityRealm.sanitizeForLog("a\rb\u0000c"));
        assertEquals("null", GoogleGroupsSecurityRealm.sanitizeForLog(null));
    }

    @Test
    public void groupAuthorityMaxAgeDefaultsAndClampsNegative() {
        GoogleGroupsSecurityRealm realm = realm();
        assertEquals(GoogleGroupsSecurityRealm.DEFAULT_GROUP_AUTHORITY_MAX_AGE_DAYS, realm.getGroupAuthorityMaxAgeDays());
        realm.setGroupAuthorityMaxAgeDays(-5);
        assertEquals(0, realm.getGroupAuthorityMaxAgeDays());
    }

    @Test
    public void federatedLoginServiceExposesUrlNameAndNoUserProperty() {
        GoogleFederatedLoginService service = new GoogleFederatedLoginService();
        assertEquals("googleGroupsOAuth", service.getUrlName());
        assertNull(service.getUserPropertyClass());
    }

    @Test
    public void groupCachePurgesExpiredEntriesOnceFull() throws Exception {
        GoogleGroupsSecurityRealm realm = realm();
        AtomicLong now = new AtomicLong(0);
        realm.setClock(now::get);
        AtomicInteger calls = new AtomicInteger();
        realm.setGroupResolver((email, token) -> {
            calls.incrementAndGet();
            return List.of();
        });

        for (int i = 0; i < 999; i++) {
            realm.authoritiesForLogin("user" + i + "@example.com", "t");
        }
        now.set(30_000);
        realm.authoritiesForLogin("fresh@example.com", "t");
        assertEquals(1000, realm.cachedGroupCount());

        // The cap is reached and the first 999 entries have expired; fresh@ has not.
        now.set(61_000);
        realm.authoritiesForLogin("another@example.com", "t");
        assertEquals(2, realm.cachedGroupCount());

        int before = calls.get();
        realm.authoritiesForLogin("fresh@example.com", "t");
        assertEquals("fresh entry must survive the purge and still be served from cache",
                before, calls.get());
    }
}
