package com.nsa.exception;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;

public class Exceptions {


    public static NotFoundException accountNotFound() {
        return new NotFoundException("account not found");
    }

    public static BadRequestException subjectMissing() {
        return new BadRequestException("missing subject header");
    }
}
