package de.mw.test.oauth.simple;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implements all needed OAuth endpoints for this PoC.
 */
@RestController
@Slf4j
public class OAuthRestController {
    private String clientId = "FW8nNo0WzD047sPbO93LTVodcYQM1m2e";
    private String clientSecret = "EVNs7zP9rCVnwd8wIP3y0gR04-SuakL_iUnLR-MeT8NtZ56TxWNVYTr1ML-xSQqK";

    @Data
    @Accessors(fluent = true)
    public static class LoginSession {
        private State state;
        private AuthorizationRequest clientAuthorizationRequest;
    }

    private Map<String, LoginSession> loginSessionStore = new ConcurrentHashMap<>();

    @Data
    @Accessors(fluent = true)
    public static class UserSession {
        private JWTClaimsSet userClaims;
    }

    private Map<String, UserSession> userSessionStore = new ConcurrentHashMap<>();
    private Map<String, String> accessTokenToUserSessionId = new ConcurrentHashMap<>();

    private URI getRequestUri(HttpServletRequest request) throws URISyntaxException {
        return new ServletServerHttpRequest(request).getURI();
    }


    @GetMapping("/authorize")
    public ResponseEntity<Void> authorize(HttpServletRequest request, HttpServletResponse response) throws Exception {
        AuthorizationRequest clientAuthorizationRequest = AuthorizationRequest.parse(getRequestUri(request));

        // check redirect url
        URI redirectUri = clientAuthorizationRequest.getRedirectionURI();
        if (!StringUtils.equals(redirectUri.getHost(), "localhost")) {
            return ResponseEntity.badRequest().build();
        }

        // start login session
        String loginSessionId = UUID.randomUUID().toString();
        State state = new State(UUID.randomUUID().toString());
        loginSessionStore.put(loginSessionId, new LoginSession().state(state).clientAuthorizationRequest(clientAuthorizationRequest));
        Cookie cookie = new Cookie("mw-test-oauth-simple.login-cookie", loginSessionId);
        response.addCookie(cookie);

        // redirect to authentication server
        AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), new ClientID(clientId))
                .scope(new Scope("openid", "profile", "email"))
                .state(state)
                .redirectionURI(new URI("http://localhost:8090/login"))
                .endpointURI(new URI("https://dev-t7n7711l.us.auth0.com/authorize"))
                .build();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", authorizationRequest.toURI().toString());
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login(@CookieValue("mw-test-oauth-simple.login-cookie") String loginSessionId, HttpServletRequest request, HttpServletResponse response) throws Exception {
        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(getRequestUri(request));

        // Check the returned state parameter, must match the original
        LoginSession loginSession = loginSessionStore.remove(loginSessionId);
        if (loginSession == null) {
            return ResponseEntity.badRequest().build();
        }
        if (!loginSession.state.equals(authorizationResponse.getState())) {
            return ResponseEntity.badRequest().build();
        }

        if (!authorizationResponse.indicatesSuccess()) {
            // The request was denied or some error occurred
            AuthorizationErrorResponse errorResponse = authorizationResponse.toErrorResponse();
            log.warn("rejected authorization response: {}", errorResponse.getErrorObject());
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        AuthorizationSuccessResponse successAuthorizationResponse = authorizationResponse.toSuccessResponse();
        AuthorizationCode code = successAuthorizationResponse.getAuthorizationCode();

        // fetch tokens from code
        ClientAuthentication tokenRequestAuth = new ClientSecretPost(new ClientID(clientId), new Secret(clientSecret));
        AuthorizationGrant tokenRequestGrant = new AuthorizationCodeGrant(code, new URI("http://localhost:8090/login"));
        TokenRequest tokenRequest = new TokenRequest(new URI("https://dev-t7n7711l.us.auth0.com/oauth/token"),
                tokenRequestAuth, tokenRequestGrant);
        HTTPResponse responsefromTokenEndpoint = tokenRequest.toHTTPRequest().send();
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(responsefromTokenEndpoint);
        if (!tokenResponse.indicatesSuccess()) {
            log.warn("token request error response: {} {}", responsefromTokenEndpoint.getStatusCode(), tokenResponse.toErrorResponse());
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
        JWT idToken = successResponse.getOIDCTokens().getIDToken();

        // create user session
        UserSession userSession = new UserSession().userClaims(idToken.getJWTClaimsSet());
        log.info("authenticated user: {}", userSession);
        String userSessionId = UUID.randomUUID().toString();
        userSessionStore.put(userSessionId, userSession);
        // create authorization code
        String clientAuthorizationCode = UUID.randomUUID().toString();
        accessTokenToUserSessionId.put(clientAuthorizationCode, userSessionId);

        // remove login session cookie
        Cookie cookie = new Cookie("mw-test-oauth-simple.login-cookie", null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        // redirect frontend to initial url and add code
        HttpHeaders headers = new HttpHeaders();
        UriComponentsBuilder frontendRedirectUri = UriComponentsBuilder.fromUri(loginSession.clientAuthorizationRequest.getRedirectionURI());
        frontendRedirectUri.queryParam("code", clientAuthorizationCode);
        headers.add("Location", frontendRedirectUri.toUriString());
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @PostMapping("/token")
    public ResponseEntity<JSONObject> token(HttpServletRequest request, HttpServletResponse response) throws Exception {
        TokenRequest tokenRequest = TokenRequest.parse(JakartaServletUtils.createHTTPRequest(request));
        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
        // todo check client authentication

        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
        log.info("client {} calls token endpoint type {}", clientAuthentication.getClientID(), authorizationGrant.getType());

        if (authorizationGrant.getType() == GrantType.AUTHORIZATION_CODE) {
            AuthorizationCode authorizationCode = ((AuthorizationCodeGrant) authorizationGrant).getAuthorizationCode();

            String userSessionId = accessTokenToUserSessionId.remove(authorizationCode.getValue());
            if (userSessionId == null) {
                log.warn("rejected token request with authorizationCode: {}", authorizationCode);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            UserSession userSession = userSessionStore.get(userSessionId);
            if (userSession == null) {
                log.warn("unknown session with userSessionId: {}", userSessionId);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            String accessToken = UUID.randomUUID().toString();
            accessTokenToUserSessionId.put(accessToken, userSessionId);
            AccessTokenResponse accessTokenResponse = new AccessTokenResponse(new Tokens(
                    new BearerAccessToken(accessToken, 300, null),
                    new RefreshToken(userSessionId)));
            return ResponseEntity.ok(accessTokenResponse.toJSONObject());
        }
        if (authorizationGrant.getType() == GrantType.REFRESH_TOKEN) {
            RefreshToken refreshToken = ((RefreshTokenGrant) authorizationGrant).getRefreshToken();
            String userSessionId = refreshToken.getValue();
            String accessToken = UUID.randomUUID().toString();
            accessTokenToUserSessionId.put(accessToken, userSessionId);
            AccessTokenResponse accessTokenResponse = new AccessTokenResponse(new Tokens(
                    new BearerAccessToken(accessToken, 300, null),
                    new RefreshToken(userSessionId)));
            return ResponseEntity.ok(accessTokenResponse.toJSONObject());
        }

        return ResponseEntity.badRequest().build();
    }
}
