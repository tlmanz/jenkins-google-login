package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

public class CloudIdentityDirectGroupResolverTest {

    private static final String EMAIL = "alice@example.com";
    private static final String TOKEN = "access-token-123";

    /** Serves a fixed sequence of responses and records the requested URLs and headers. */
    private static final class SequencedTransport extends MockHttpTransport {
        final List<String> urls = new ArrayList<>();
        final List<String> authorizations = new ArrayList<>();
        private final List<MockLowLevelHttpResponse> responses;
        private int index;

        SequencedTransport(MockLowLevelHttpResponse... responses) {
            this.responses = List.of(responses);
        }

        @Override
        public LowLevelHttpRequest buildRequest(String method, String url) {
            urls.add(url);
            MockLowLevelHttpResponse response = responses.get(Math.min(index++, responses.size() - 1));
            return new MockLowLevelHttpRequest(url) {
                @Override
                public LowLevelHttpResponse execute() throws IOException {
                    authorizations.addAll(getHeaderValues("authorization"));
                    return response;
                }
            };
        }
    }

    private static MockLowLevelHttpResponse jsonResponse(String body) {
        return new MockLowLevelHttpResponse().setContentType(Json.MEDIA_TYPE).setContent(body);
    }

    @Test
    public void resolvesGroupsAcrossPagesLowercasedAndDeduplicated() throws Exception {
        SequencedTransport transport = new SequencedTransport(
                jsonResponse("{\"memberships\":["
                        + "{\"groupKey\":{\"id\":\"Jenkins-QA@Example.com\"},\"displayName\":\"QA\"},"
                        + "{\"groupKey\":{\"id\":\"jenkins-admins@example.com\"}}"
                        + "],\"nextPageToken\":\"page2\"}"),
                jsonResponse("{\"memberships\":["
                        + "{\"groupKey\":{\"id\":\"jenkins-qa@example.com\"}},"
                        + "{\"groupKey\":{\"id\":\"other-team@example.com\"}}"
                        + "]}"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);

        List<String> groups = resolver.resolveGroups(EMAIL, TOKEN);

        assertEquals(List.of("jenkins-qa@example.com", "jenkins-admins@example.com", "other-team@example.com"),
                groups);
        assertEquals(2, transport.urls.size());
        String firstUrl = URLDecoder.decode(transport.urls.get(0), StandardCharsets.UTF_8);
        assertTrue(firstUrl.startsWith(CloudIdentityDirectGroupResolver.SEARCH_URL));
        assertTrue(firstUrl.contains("member_key_id == 'alice@example.com'"));
        assertTrue(URLDecoder.decode(transport.urls.get(1), StandardCharsets.UTF_8).contains("pageToken=page2"));
        assertEquals(List.of("Bearer " + TOKEN, "Bearer " + TOKEN), transport.authorizations);
    }

    @Test
    public void includePatternFiltersGroups() throws Exception {
        SequencedTransport transport = new SequencedTransport(
                jsonResponse("{\"memberships\":["
                        + "{\"groupKey\":{\"id\":\"jenkins-qa@example.com\"}},"
                        + "{\"groupKey\":{\"id\":\"all-staff@example.com\"}},"
                        + "{\"groupKey\":{\"id\":\"jenkins-admins@example.com\"}}"
                        + "]}"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(
                transport, Pattern.compile("^jenkins-.*@example\\.com$"));

        assertEquals(List.of("jenkins-qa@example.com", "jenkins-admins@example.com"),
                resolver.resolveGroups(EMAIL, TOKEN));
    }

    @Test
    public void emptyMembershipListYieldsNoGroups() throws Exception {
        SequencedTransport transport = new SequencedTransport(jsonResponse("{}"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);
        assertEquals(List.of(), resolver.resolveGroups(EMAIL, TOKEN));
    }

    @Test
    public void httpErrorPropagatesAsException() {
        SequencedTransport transport = new SequencedTransport(
                new MockLowLevelHttpResponse().setStatusCode(403).setContentType(Json.MEDIA_TYPE)
                        .setContent("{\"error\":{\"status\":\"PERMISSION_DENIED\"}}"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);
        assertThrows(HttpResponseException.class, () -> resolver.resolveGroups(EMAIL, TOKEN));
    }

    @Test
    public void malformedJsonPropagatesAsIOException() {
        SequencedTransport transport = new SequencedTransport(jsonResponse("this is not json"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);
        assertThrows(IOException.class, () -> resolver.resolveGroups(EMAIL, TOKEN));
    }

    @Test
    public void paginationStopsAtCapInsteadOfLoopingForever() throws Exception {
        // Every page advertises another one: the resolver must stop at its cap. A fresh
        // response is built per request because mock response streams are single-use.
        List<String> urls = new ArrayList<>();
        MockHttpTransport transport = new MockHttpTransport() {
            @Override
            public LowLevelHttpRequest buildRequest(String method, String url) {
                urls.add(url);
                return new MockLowLevelHttpRequest(url) {
                    @Override
                    public LowLevelHttpResponse execute() {
                        return jsonResponse("{\"memberships\":[{\"groupKey\":{\"id\":\"g@example.com\"}}],"
                                + "\"nextPageToken\":\"again\"}");
                    }
                };
            }
        };
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);
        assertEquals(List.of("g@example.com"), resolver.resolveGroups(EMAIL, TOKEN));
        assertEquals(50, urls.size());
    }

    @Test
    public void malformedMembershipEntriesAreSkippedAndEmptyPageTokenEndsPaging() throws Exception {
        SequencedTransport transport = new SequencedTransport(jsonResponse(
                "{\"memberships\":[42,{\"other\":1},{\"groupKey\":{}},{\"groupKey\":{\"id\":\"ok@example.com\"}}],"
                        + "\"nextPageToken\":\"\"}"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);
        assertEquals(List.of("ok@example.com"), resolver.resolveGroups(EMAIL, TOKEN));
        assertEquals(1, transport.urls.size());
    }

    @Test
    public void emailWithQuoteIsRejectedWithoutAnyRequest() {
        SequencedTransport transport = new SequencedTransport(jsonResponse("{}"));
        CloudIdentityDirectGroupResolver resolver = new CloudIdentityDirectGroupResolver(transport, null);
        assertThrows(IOException.class, () -> resolver.resolveGroups("a'||'b@example.com", TOKEN));
        assertEquals(0, transport.urls.size());
    }
}
