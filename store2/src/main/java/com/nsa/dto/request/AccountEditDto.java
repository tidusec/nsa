package com.nsa.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AccountEditDto {
    @NotBlank
    public String firstname;
    @NotBlank
    public String lastname;
    @NotBlank
    @Email
    public String email;
    public String password;
}
