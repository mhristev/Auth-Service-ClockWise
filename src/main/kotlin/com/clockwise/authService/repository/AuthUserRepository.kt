package com.clockwise.authService.repository

import com.clockwise.authService.domain.AuthUser
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository

@Repository
interface AuthUserRepository : CoroutineCrudRepository<AuthUser, String> {
    suspend fun findByEmail(email: String): AuthUser?
    suspend fun findByKeycloakUserId(keycloakUserId: String): AuthUser?
    suspend fun existsByEmail(email: String): Boolean
} 