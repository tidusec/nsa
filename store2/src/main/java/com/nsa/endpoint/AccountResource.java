package com.nsa.endpoint;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.nsa.dto.request.AccountCreateDto;
import com.nsa.dto.request.AccountDetailDto;
import com.nsa.dto.request.AccountEditDto;
import com.nsa.dto.request.AccountLoginDto;
import com.nsa.dto.request.ProfilePictureUpdateDto;
import com.nsa.dto.response.AccountListDto;
import com.nsa.dto.response.AccountSubordinatesExtendedListDto;
import com.nsa.dto.response.AccountSubordinatesListDto;
import com.nsa.dto.response.LoginResponseDto;
import com.nsa.entity.Account;
import com.nsa.exception.Exceptions;
import io.quarkus.panache.common.Sort;
import io.quarkus.security.Authenticated;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.ResponseStatus;
import org.jboss.resteasy.reactive.RestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;

@Path("/accounts")
@ApplicationScoped
public class AccountResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccountResource.class);

    // The header value is also available as the SecurityIdentity's principal
    @HeaderParam("NSA-Subject")
    Optional<String> subject;

    @ResponseStatus(RestResponse.StatusCode.CREATED)
    @POST
    @Transactional
    public void create(@Valid AccountCreateDto dto) {
        if (Account.find("username", dto.username).count() != 0) {
            throw new ClientErrorException("account already exists", Response.Status.CONFLICT);
        }

        Account account = new Account();
        account.email = dto.email;
        account.password = BCrypt.withDefaults().hashToString(12, dto.password.toCharArray());
        account.username = dto.username;
        account.persist();
    }

    /**
     * Use jwt token with <code>Authorization: Bearer</code> header.
     */
    @POST
    @Path("login")
    public LoginResponseDto login(@Valid AccountLoginDto dto) {
        Account account = Account.find("username", dto.username)
            .<Account>firstResultOptional()
            .orElseThrow(Exceptions::accountNotFound);

        BCrypt.Result pwCheckResult = BCrypt.verifyer().verify(dto.password.toCharArray(), account.password);
        if (!pwCheckResult.verified) {
            throw new NotAuthorizedException("password does not match");
        }

        return new LoginResponseDto(dto.username);
    }

    @PUT
    @Authenticated
    @Transactional
    @Path("{username}/edit")
    public void updateAccountDetails(@PathParam("username") String username, @Valid AccountEditDto dto) {
        Account account = Account.find("username", username)
            .<Account>firstResultOptional()
            .orElseThrow(Exceptions::accountNotFound);

        String currentUsername = subject.orElseThrow(Exceptions::subjectMissing);

        if (!currentUsername.equals(username)) {
            throw new ForbiddenException("you are not authorized to update this account");
        }

        account.firstname = dto.firstname;
        account.lastname = dto.lastname;
        account.email = dto.email;
        if (dto.password != null && !dto.password.isBlank()) {
            account.password = BCrypt.withDefaults().hashToString(12, dto.password.toCharArray());
        }

        account.persist();
    }

    @PUT
    @Transactional
    @Path("{username}/profilePicture")
    public void updateProfilePicture(@PathParam("username") String username, @Valid ProfilePictureUpdateDto dto, @QueryParam("register") boolean isRegistration) {
        Account account = Account.find("username", username)
            .<Account>firstResultOptional()
            .orElseThrow(Exceptions::accountNotFound);

        if (!isRegistration) {
            String currentUsername = subject.orElseThrow(Exceptions::subjectMissing);
            if (!currentUsername.equals(username)) {
                throw new ForbiddenException("you are not authorized to update this account");
            }
        }

        try {
            account.profilePicture = fetchImageFromUrl(dto.profilePictureUrl);
            account.persist();
        } catch (IOException | InterruptedException e) {
            throw new BadRequestException("invalid profile picture URL or content");
        }
    }

    @GET
    @Path("{username}/profilePicture")
    @Produces({"image/jpg", "image/png"})
    public byte[] getProfilePicture(@PathParam("username") String username) {
        Account account = Account.find("username", username)
            .<Account>firstResultOptional()
            .orElseThrow(Exceptions::accountNotFound);
        return account.profilePicture;
    }

    @GET
    @Authenticated
    @Path("subordinates")
    public List<? extends AccountSubordinatesListDto> getSubordinates() {
        Account account = Account.<Account>findByIdOptional(subject.orElseThrow(Exceptions::subjectMissing))
            .orElseThrow(Exceptions::accountNotFound);

        var query = Account.find("from Account where permissionLevel <= ?1", Sort.by("username"), account.permissionLevel);
        if(account.isSuperAdmin()) {
            return query.project(AccountSubordinatesExtendedListDto.class).list();
        }

        return query.project(AccountSubordinatesListDto.class).list();
    }

    @POST
    @Authenticated
    @Transactional
    @Path("{username}/promote")
    public void promote(@PathParam("username") String username) {
        Account actor = Account.<Account>findByIdOptional(subject.orElseThrow(Exceptions::subjectMissing))
            .orElseThrow(Exceptions::accountNotFound);
        Account target = Account.<Account>findByIdOptional(username)
            .orElseThrow(Exceptions::accountNotFound);

        if (actor.permissionLevel <= target.permissionLevel) {
            throw new NotAuthorizedException("cannot promote account");
        }

        target.permissionLevel++;
        target.persist();
    }

    @POST
    @Authenticated
    @Transactional
    @Path("{username}/demote")
    public void demote(@PathParam("username") String username) {
        Account actor = Account.<Account>findByIdOptional(subject.orElseThrow(Exceptions::subjectMissing))
            .orElseThrow(Exceptions::accountNotFound);
        Account target = Account.<Account>findByIdOptional(username)
            .orElseThrow(Exceptions::accountNotFound);

        if (actor.permissionLevel < target.permissionLevel) {
            throw new NotAuthorizedException("cannot demote account");
        }

        target.permissionLevel--;
        target.persist();
    }

    @GET
    @Path("{username}")
    @Authenticated
    public AccountDetailDto userDetails(@PathParam("username") String username) {
        Account actor = Account.<Account>findByIdOptional(subject.orElseThrow(Exceptions::subjectMissing))
            .orElseThrow(Exceptions::accountNotFound);
        Account target = Account.<Account>findByIdOptional(username)
            .orElseThrow(Exceptions::accountNotFound);
        if (actor.permissionLevel < target.permissionLevel) {
            throw new ForbiddenException("you are not authorized to query this account");
        }
        return new AccountDetailDto(target.firstname,
            target.lastname,
            target.username,
            target.email,
            target.role,
            target.permissionLevel,
            target.securityClearance,
            target.biometricFingerprint);
    }

    private byte[] fetchImageFromUrl(String profilePictureUrl) throws IOException, InterruptedException {
        URI uri = URI.create(profilePictureUrl);
        if (!uri.getRawPath().endsWith(".png") && !uri.getRawPath().endsWith(".jpg")) {
            throw new BadRequestException("invalid profile picture URL");
        }
        try (HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build()) {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .GET()
                .build();
            boolean isLocalHost = isThisMyIpAddress(InetAddress.getByName(request.uri().getHost()));
            if (isLocalHost) {
               throw new ForbiddenException("forbidden URL");
            }
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            
            return response.body();
        }


    }

    @POST
    @Path("/register")
    @Transactional
    public Response register(@Valid AccountCreateDto dto) {
        // Check if the account already exists
        if (Account.find("username", dto.username).count() != 0) {
            throw new WebApplicationException(
                Response.status(Response.Status.CONFLICT)
                    .entity("Agent ID already exists")
                    .build()
            );
        }

        // Create new account
        Account account = new Account();
        account.username = dto.username;
        account.firstname = dto.firstname;
        account.lastname = dto.lastname;
        account.email = dto.email;
        // Hash password using BCrypt with a cost factor of 12
        account.password = BCrypt.withDefaults().hashToString(12, dto.password.toCharArray());
        account.biometricFingerprint = dto.biometricFingerprint;
        account.persist();

        // Return success response
        return Response.status(Response.Status.CREATED).entity("Account created successfully").build();
    }


    // https://stackoverflow.com/a/2406819/7448536
    public static boolean isThisMyIpAddress(InetAddress addr) {
        // Check if the address is a valid special local or loop back
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress())
            return true; // Was local sub-net.

        // Check if the Non-local address is defined on any Local-interface.
        try {
            return NetworkInterface.getByInetAddress(addr) != null;
        } catch (SocketException e) {
            return false;
        }
    }
}
