package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

public class GroupLookupFailurePolicyTest {

    private static final String EMAIL = "alice@example.com";
    private static final String TOKEN = "access-token";

    private static GoogleGroupsSecurityRealm realm() {
        return new GoogleGroupsSecurityRealm("client-id", null, "example.com");
    }

    private static List<String> names(List<GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Test
    public void groupsBecomeAuthoritiesAfterAuthenticated() throws Exception {
        GoogleGroupsSecurityRealm realm = realm();
        realm.setGroupResolver((email, token) -> List.of("jenkins-qa@example.com", "jenkins-admins@example.com"));
        assertEquals(List.of("authenticated", "jenkins-qa@example.com", "jenkins-admins@example.com"),
                names(realm.authoritiesForLogin(EMAIL, TOKEN)));
    }

    @Test
    public void degradePolicyFallsBackToAuthenticatedOnly() throws Exception {
        GoogleGroupsSecurityRealm realm = realm();
        realm.setOnGroupLookupFailure(GroupLookupFailurePolicy.DEGRADE);
        realm.setGroupResolver((email, token) -> {
            throw new IOException("boom");
        });
        assertEquals(List.of("authenticated"), names(realm.authoritiesForLogin(EMAIL, TOKEN)));
    }

    @Test
    public void failPolicyRethrows() {
        GoogleGroupsSecurityRealm realm = realm();
        realm.setOnGroupLookupFailure(GroupLookupFailurePolicy.FAIL);
        realm.setGroupResolver((email, token) -> {
            throw new IOException("boom");
        });
        assertThrows(IOException.class, () -> realm.authoritiesForLogin(EMAIL, TOKEN));
    }

    @Test
    public void failPolicyWrapsRuntimeExceptions() {
        GoogleGroupsSecurityRealm realm = realm();
        realm.setOnGroupLookupFailure(GroupLookupFailurePolicy.FAIL);
        realm.setGroupResolver((email, token) -> {
            throw new IllegalStateException("boom");
        });
        assertThrows(IOException.class, () -> realm.authoritiesForLogin(EMAIL, TOKEN));
    }

    @Test
    public void successfulLookupIsCachedFor60Seconds() throws Exception {
        GoogleGroupsSecurityRealm realm = realm();
        AtomicInteger calls = new AtomicInteger();
        AtomicLong now = new AtomicLong(1_000_000L);
        realm.setClock(now::get);
        realm.setGroupResolver((email, token) -> {
            calls.incrementAndGet();
            return List.of("jenkins-qa@example.com");
        });

        realm.authoritiesForLogin(EMAIL, TOKEN);
        realm.authoritiesForLogin(EMAIL, TOKEN);
        assertEquals(1, calls.get());

        now.addAndGet(61_000L);
        realm.authoritiesForLogin(EMAIL, TOKEN);
        assertEquals(2, calls.get());
    }

    @Test
    public void failureIsNotCached() throws Exception {
        GoogleGroupsSecurityRealm realm = realm();
        AtomicInteger calls = new AtomicInteger();
        realm.setGroupResolver((email, token) -> {
            if (calls.incrementAndGet() == 1) {
                throw new IOException("transient");
            }
            return List.of("jenkins-qa@example.com");
        });

        assertEquals(List.of("authenticated"), names(realm.authoritiesForLogin(EMAIL, TOKEN)));
        assertEquals(List.of("authenticated", "jenkins-qa@example.com"),
                names(realm.authoritiesForLogin(EMAIL, TOKEN)));
    }
}
