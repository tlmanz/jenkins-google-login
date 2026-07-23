package io.jenkins.plugins.googlegroupsoauth;

/**
 * What to do when the Google Groups lookup fails at login time (network error, HTTP 4xx/5xx,
 * malformed response). A failure is never silently cached as "no groups".
 */
public enum GroupLookupFailurePolicy {
    /**
     * Log the user in with only the {@code authenticated} authority and emit a loud WARNING.
     * The user regains group-based permissions at their next successful login.
     */
    DEGRADE,
    /** Refuse the login. */
    FAIL
}
