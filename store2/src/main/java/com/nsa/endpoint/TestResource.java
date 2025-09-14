package com.nsa.endpoint;

import com.nsa.entity.Account;
import com.nsa.exception.Exceptions;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Path("/test")
@ApplicationScoped
public class TestResource {

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
        checkIsLocalhost();

        Account account = Account.<Account>findByIdOptional(username)
            .orElseThrow(Exceptions::accountNotFound);
        account.permissionLevel = Account.SUPER_ADMIN_PERMISSION_LEVEL;
        account.persist();
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
