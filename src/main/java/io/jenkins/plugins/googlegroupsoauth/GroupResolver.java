package io.jenkins.plugins.googlegroupsoauth;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.util.List;

/**
 * Resolves the Google Groups a user belongs to.
 *
 * <p>Pluggable so that a future service-account mode (Cloud Identity Groups Reader role or
 * Admin SDK Directory API with domain-wide delegation) can be added without redesigning the
 * realm. The v1 implementation is {@link CloudIdentityDirectGroupResolver}, which uses the
 * logged-in user's own OAuth access token.
 */
public interface GroupResolver {

    /**
     * @param email the logged-in user's primary email (lowercase)
     * @param accessToken an OAuth access token authorized to look up the user's groups
     * @return group emails (lowercase), possibly empty; never null
     * @throws IOException on any lookup failure (network, HTTP 4xx/5xx, malformed response)
     */
    @NonNull
    List<String> resolveGroups(@NonNull String email, @NonNull String accessToken) throws IOException;
}
