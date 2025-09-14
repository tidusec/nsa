package com.nsa.endpoint;

import com.nsa.entity.Account;
import com.nsa.exception.Exceptions;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Path("/test")
@ApplicationScoped
public class TestResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestResource.class);

    @Inject
    RoutingContext context;

    @GET
    @Path("{username}")
    public Account get(@PathParam("username") String username) {
        checkIsLocalhost();

        return Account.<Account>findByIdOptional(username)
            .orElseThrow(Exceptions::accountNotFound);
    }

    @POST
    @Path("{username}/superAdmin")
    public void superAdmin(@PathParam("username") String username) {
        // Enhanced security checks for privilege escalation
        checkIsLocalhost();
        
        // Additional security: require specific environment variable to be set
        String adminEscalationKey = System.getenv("NSA_ADMIN_ESCALATION_KEY");
        if (adminEscalationKey == null || adminEscalationKey.isEmpty()) {
            throw new ForbiddenException("admin escalation not enabled");
        }
        
        // Log this critical operation
        LOGGER.warn("SECURITY: Super admin privilege escalation attempted for user: {}", username);

        Account account = Account.<Account>findByIdOptional(username)
            .orElseThrow(Exceptions::accountNotFound);
        account.permissionLevel = Account.SUPER_ADMIN_PERMISSION_LEVEL;
        account.persist();
        
        LOGGER.warn("SECURITY: Super admin privilege escalation completed for user: {}", username);
    }

    private void checkIsLocalhost() {
        try {
            String requestAddress = context.request().remoteAddress().hostAddress();
            boolean isLocalHost = InetAddress.getByName(requestAddress).isLoopbackAddress();
            if(!isLocalHost) {
                throw new ForbiddenException("only localhost allowed");
            }
        } catch (UnknownHostException e) {
            throw new BadRequestException(e);
        }
    }
}
