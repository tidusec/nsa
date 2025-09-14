package com.nsa.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AccountCreateDto {
    @NotBlank
    public String username;
    @NotBlank
    public String firstname;
    @NotBlank
    public String lastname;
    @NotBlank
    @Email
    public String email;
    @NotBlank
    public String password;
    public String biometricFingerprint;
}
