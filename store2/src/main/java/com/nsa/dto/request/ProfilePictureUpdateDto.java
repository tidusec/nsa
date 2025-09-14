package com.nsa.dto.request;

import jakarta.validation.constraints.NotBlank;

public class ProfilePictureUpdateDto {
    @NotBlank
    public String profilePictureUrl;
}
