package com.nsa;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;


@Alternative
@ApplicationScoped
@Priority(1)
public class NsaSubjectAuthMechanism implements HttpAuthenticationMechanism {

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context,
                                              IdentityProviderManager identityProviderManager) {
        String subject = context.request().getHeader("NSA-Subject");
        if (subject == null || subject.trim().isEmpty()) {
            return Uni.createFrom().nullItem();
        }

        // Create a security identity with the subject
        QuarkusSecurityIdentity identity = QuarkusSecurityIdentity.builder()
            .setPrincipal(() -> subject)
            .build();

        return Uni.createFrom().item(identity);
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        // Return 401 when authentication is required
        return Uni.createFrom()
            .item(new ChallengeData(HttpResponseStatus.UNAUTHORIZED.code(), "WWW-Authenticate", "NSA-Subject"));
    }
}