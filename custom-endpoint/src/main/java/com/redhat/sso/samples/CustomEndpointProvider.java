package com.redhat.sso.samples;

import java.util.Map;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

public class CustomEndpointProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;

    private static final String SPECIAL_ROLE = "special_token";

    public CustomEndpointProvider(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    @Override
    public void close() {}

    @Override
    public Object getResource() {
        return this;
    }

    @POST
	@Path("token")
	@Produces(MediaType.APPLICATION_JSON)
	public Response tokenAnonymous(@QueryParam("issuer") String issuer,
                                   @QueryParam("transactionID") String transactionID,
                                   @QueryParam("transactionName") String transactionName) {
        String token = signToken(createAccessToken(issuer, transactionID, transactionName));
        return Response.ok(Map.of("access_token", token)).build();
	}

    @POST
    @Path("/secure/token")
    @Produces(MediaType.APPLICATION_JSON)
    public Response tokenSecure(@QueryParam("issuer") String issuer,
                                @QueryParam("transactionID") String transactionID,
                                @QueryParam("transactionName") String transactionName) {
        if (auth != null) {
            String token = signToken(createAccessToken(issuer, transactionID, transactionName));
            return Response.ok(Map.of("access_token", token)).build();
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @POST
    @Path("/secure-jwt/token")
    @Produces(MediaType.APPLICATION_JSON)
    public Response tokenJwt(   @QueryParam("issuer") String issuer,
                                @QueryParam("transactionID") String transactionID,
                                @QueryParam("transactionName") String transactionName,
                                @HeaderParam("Authorization") String authorizationHeaderValue) {
        if (authorizationHeaderValue != null){
            String authToken = authorizationHeaderValue.substring(7, authorizationHeaderValue.length());
            if (isValidJwt(authToken)){
                String token = signToken(createAccessToken(issuer, transactionID, transactionName));
                return Response.ok(Map.of("access_token", token)).build();
            }
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    private AccessToken createAccessToken(String issuer, String transactionID, String transactionName) {
        AccessToken token = new AccessToken();
        token.issuer(issuer);
        token.setOtherClaims("transactionID", transactionID);
        token.setOtherClaims("transactionName", transactionName);
        token.issuedNow();
        token.expiration((int) (token.getIat() + 120L));
        return token;
    }

    private String signToken(AccessToken token) {
        KeyManager.ActiveRsaKey key = session.keys().getActiveRsaKey(session.getContext().getRealm());
        String signedToken = new JWSBuilder()
                .kid(key.getKid())
                .type("JWT")
                .jsonContent(token)
                .rsa256(key.getPrivateKey());
        return signedToken;
    }

    private boolean isValidJwt(String token){
        try {
            AccessToken accessToken = TokenVerifier.create(token, AccessToken.class).getToken();
            return accessToken.getRealmAccess().getRoles().contains(SPECIAL_ROLE);
        } catch (VerificationException e) {
            System.out.println("Error checking token");
            e.printStackTrace();
            return false;
        }
    }
    
}
