package com.clockwise.authService.domain

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.relational.core.mapping.Column
import java.time.LocalDateTime
import java.util.UUID

enum class AuthUserStatus {
    ACTIVE, INACTIVE, SUSPENDED
}

/**
 * Represents authentication credentials and basic profile in Auth Service
 * This is separate from business context stored in User Service
 */
@Table("auth_users")
data class AuthUser(
    @Id
    @Column("id")
    val id: String? = null,
    val email: String,
    @Column("first_name")
    val firstName: String,
    @Column("last_name")
    val lastName: String,
    @Column("phone_number")
    val phoneNumber: String? = null,
    @Column("keycloak_user_id")
    val keycloakUserId: String,  // Reference to Keycloak user
    val status: AuthUserStatus = AuthUserStatus.ACTIVE,
    @Column("email_verified")
    val emailVerified: Boolean = false,
    @Column("created_at")
    val createdAt: LocalDateTime = LocalDateTime.now(),
    @Column("updated_at")
    val updatedAt: LocalDateTime = LocalDateTime.now()
) {
    companion object {
        fun newUser(
            email: String,
            firstName: String,
            lastName: String,
            phoneNumber: String?,
            keycloakUserId: String
        ): AuthUser {
            return AuthUser(
                id = UUID.randomUUID().toString(),
                email = email,
                firstName = firstName,
                lastName = lastName,
                phoneNumber = phoneNumber,
                keycloakUserId = keycloakUserId,
                status = AuthUserStatus.ACTIVE,
                emailVerified = false,
                createdAt = LocalDateTime.now(),
                updatedAt = LocalDateTime.now()
            )
        }
    }
} 