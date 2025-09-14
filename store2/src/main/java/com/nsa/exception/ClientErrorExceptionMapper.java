package com.nsa.exception;

import com.nsa.dto.response.ErrorDto;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class ClientErrorExceptionMapper implements ExceptionMapper<ClientErrorException> {
    @Override
    public Response toResponse(ClientErrorException exception) {
        return Response.status(exception.getResponse().getStatus()).type(MediaType.APPLICATION_JSON_TYPE).entity(new ErrorDto(exception.getMessage())).build();
    }
}
