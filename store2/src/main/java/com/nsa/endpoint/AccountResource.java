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
import java.time.Duration;
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

        // Only return accounts with strictly lower permission levels (subordinates)
        // Remove the equals condition to prevent lateral movement
        var query = Account.find("from Account where permissionLevel < ?1", Sort.by("username"), account.permissionLevel);
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
        
        // Enhanced validation for file extension
        String path = uri.getRawPath();
        if (path == null || (!path.toLowerCase().endsWith(".png") && !path.toLowerCase().endsWith(".jpg") && !path.toLowerCase().endsWith(".jpeg"))) {
            throw new BadRequestException("invalid profile picture URL - must end with .png, .jpg, or .jpeg");
        }
        
        // Enhanced SSRF protection
        String host = uri.getHost();
        if (host == null) {
            throw new BadRequestException("invalid URL - no host specified");
        }
        
        // Check for blocked hosts and IP ranges
        if (isBlockedHost(host)) {
            throw new ForbiddenException("forbidden URL - blocked host");
        }
        
        InetAddress address = InetAddress.getByName(host);
        
        // Block all local, loopback, and private network addresses
        if (address.isLoopbackAddress() || 
            address.isAnyLocalAddress() || 
            address.isLinkLocalAddress() ||
            address.isSiteLocalAddress() ||
            isPrivateIP(address)) {
            throw new ForbiddenException("forbidden URL - private/local address not allowed");
        }
        
        // Additional check if this resolves to a local interface
        if (isThisMyIpAddress(address)) {
            throw new ForbiddenException("forbidden URL - resolves to local interface");
        }
        
        try (HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(10))
            .build()) {
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
                
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            
            // Validate response
            if (response.statusCode() != 200) {
                throw new BadRequestException("failed to fetch image - HTTP " + response.statusCode());
            }
            
            // Check content type
            String contentType = response.headers().firstValue("content-type").orElse("");
            if (!contentType.startsWith("image/")) {
                throw new BadRequestException("invalid content type - must be an image");
            }
            
            // Check file size (limit to 5MB)
            byte[] body = response.body();
            if (body.length > 5 * 1024 * 1024) {
                throw new BadRequestException("image too large - maximum 5MB allowed");
            }
            
            return body;
        }
    }
    
    private boolean isBlockedHost(String host) {
        // Block common internal/localhost variations
        String lowerHost = host.toLowerCase();
        return lowerHost.equals("localhost") ||
               lowerHost.equals("127.0.0.1") ||
               lowerHost.equals("::1") ||
               lowerHost.equals("0.0.0.0") ||
               lowerHost.matches("127\\.\\d+\\.\\d+\\.\\d+") ||
               lowerHost.matches("0\\.\\d+\\.\\d+\\.\\d+") ||
               lowerHost.contains("169.254.169.254") || // AWS metadata
               lowerHost.contains("metadata.google.internal") || // GCP metadata
               lowerHost.contains("kubernetes.default") || // K8s internal
               lowerHost.contains(".internal") ||
               lowerHost.contains(".local");
    }
    
    private boolean isPrivateIP(InetAddress addr) {
        byte[] ip = addr.getAddress();
        
        // IPv4 private ranges
        if (ip.length == 4) {
            int first = ip[0] & 0xFF;
            int second = ip[1] & 0xFF;
            
            // 10.0.0.0/8
            if (first == 10) return true;
            
            // 172.16.0.0/12
            if (first == 172 && second >= 16 && second <= 31) return true;
            
            // 192.168.0.0/16
            if (first == 192 && second == 168) return true;
            
            // 169.254.0.0/16 (link-local)
            if (first == 169 && second == 254) return true;
        }
        
        return false;
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
