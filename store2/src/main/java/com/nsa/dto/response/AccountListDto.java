package com.nsa.dto.response;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record AccountListDto(String username, String email) {
}
