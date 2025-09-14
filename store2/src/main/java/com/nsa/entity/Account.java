package com.nsa.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.*;

import static jakarta.persistence.FetchType.LAZY;


@Entity
public class Account extends PanacheEntityBase {

    public static final byte SUPER_ADMIN_PERMISSION_LEVEL = Byte.MAX_VALUE;

    @Id
    @Column(length = 40, nullable = false)
    public String username;

    /**
     * Uses bcrypt
     */
    @Column(length = 72, nullable = false)
    public String password;

    @Column(nullable = false)
    public String email;

    @Column(nullable = false)
    public String firstname = "";

    @Column(nullable = false)
    public String lastname = "";

    /**
     * A png file
     */
    @Column()
    @Basic(fetch=LAZY)
    public byte[] profilePicture = new byte[0];

    @Column()
    @Enumerated(EnumType.STRING)
    public Role role = Role.NONE;

    @Column()
    public byte permissionLevel = 0;

    @Column()
    @Enumerated(EnumType.STRING)
    public Clearance securityClearance = Clearance.NONE;

    @Column()
    public String biometricFingerprint;

    public boolean isSuperAdmin() {
        return permissionLevel == SUPER_ADMIN_PERMISSION_LEVEL;
    }

    public enum Role {
        NONE, VISITOR, USER, ADMIN
    }

    public enum Clearance {
        NONE, SOME, ALL
    }

}
