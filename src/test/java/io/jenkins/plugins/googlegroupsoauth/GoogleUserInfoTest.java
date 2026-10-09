package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import org.junit.jupiter.api.Test;

public class GoogleUserInfoTest {

    private static GoogleIdToken.Payload payload(String email, Object name) {
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setSubject("1234567890");
        payload.setEmail(email);
        if (name != null) {
            payload.set("name", name);
        }
        return payload;
    }

    @Test
    public void emailIsLowercased() {
        assertEquals("alice@example.com", new GoogleUserInfo(payload("Alice@Example.COM", "Alice")).getEmail());
    }

    @Test
    public void subjectIsExposed() {
        assertEquals("1234567890", new GoogleUserInfo(payload("a@example.com", null)).getSubject());
    }

    @Test
    public void nameClaimIsUsedWhenPresent() {
        assertEquals("Alice Example", new GoogleUserInfo(payload("a@example.com", "Alice Example")).getName());
    }

    @Test
    public void missingBlankOrNonStringNameYieldsNull() {
        assertNull(new GoogleUserInfo(payload("a@example.com", null)).getName());
        assertNull(new GoogleUserInfo(payload("a@example.com", "   ")).getName());
        assertNull(new GoogleUserInfo(payload("a@example.com", 42)).getName());
    }
}
