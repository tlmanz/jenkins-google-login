package io.jenkins.plugins.googlegroupsoauth;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import jenkins.model.Jenkins;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Debug page at {@code /securityRealm/whoami} showing the caller's user id and resolved
 * authorities. Deliberately reachable without Overall/Read: its whole point is diagnosing
 * users whose group authorities were silently filtered by Google (and who therefore may have
 * no permissions at all). It only ever shows the caller their own identity.
 */
public class WhoAmIAction {

    @NonNull
    public String getUserId() {
        return Jenkins.getAuthentication2().getName();
    }

    public boolean isAnonymous() {
        return Jenkins.getAuthentication2() instanceof AnonymousAuthenticationToken;
    }

    @NonNull
    public List<String> getAuthorities() {
        Authentication authentication = Jenkins.getAuthentication2();
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();
    }
}
