package com.nsa.dto.response;

import com.nsa.entity.Account;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.Objects;

@RegisterForReflection
public class AccountSubordinatesListDto {
    public final String username;
    public final String email;
    public final Account.Role role;
    public final byte permissionLevel;

    public AccountSubordinatesListDto(String username, String email, Account.Role role, byte permissionLevel) {
        this.username = username;
        this.email = email;
        this.role = role;
        this.permissionLevel = permissionLevel;
    }
}
