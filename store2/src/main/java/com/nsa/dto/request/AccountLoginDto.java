package com.nsa.dto.request;

import jakarta.validation.constraints.NotBlank;

public class AccountLoginDto {
    @NotBlank
    public String username;
    @NotBlank
    public String password;
}
