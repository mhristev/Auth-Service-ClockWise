package com.clockwise.authService.service

import com.clockwise.authService.domain.AuthUser
import com.clockwise.authService.domain.AuthUserStatus
import com.clockwise.authService.event.UserRegistrationEvent
import com.clockwise.authService.repository.AuthUserRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate
import kotlinx.coroutines.reactor.awaitSingle
import java.time.LocalDateTime

data class RegisterRequest(
    val email: String,
    val password: String,
    val firstName: String,
    val lastName: String,
    val phoneNumber: String? = null
)

data class LoginRequest(
    val email: String,
    val password: String
)

data class LoginResponse(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Int,
    val refreshToken: String? = null,
    val user: AuthUserDto
)

data class AuthUserDto(
    val id: String?,
    val email: String,
    val firstName: String,
    val lastName: String,
    val phoneNumber: String?,
    val keycloakUserId: String,
    val emailVerified: Boolean
)

private fun AuthUser.toDto() = AuthUserDto(
    id = id,
    email = email,
    firstName = firstName,
    lastName = lastName,
    phoneNumber = phoneNumber,
    keycloakUserId = keycloakUserId,
    emailVerified = emailVerified
)

@Service
class AuthService(
    private val authUserRepository: AuthUserRepository,
    private val keycloakService: KeycloakService,
    private val eventPublisherService: EventPublisherService,
    private val r2dbcEntityTemplate: R2dbcEntityTemplate
) {
    private val logger = LoggerFactory.getLogger(AuthService::class.java)

    @Transactional
    suspend fun registerUser(request: RegisterRequest): AuthUserDto {
        try {
            // Check if user already exists
            if (authUserRepository.existsByEmail(request.email)) {
                throw IllegalArgumentException("Email already registered")
            }

            // Create user in Keycloak
            val keycloakUserId = keycloakService.createUser(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName
            )

            // Create AuthUser record using explicit INSERT
            val authUser = AuthUser.newUser(
                email = request.email,
                firstName = request.firstName,
                lastName = request.lastName,
                phoneNumber = request.phoneNumber,
                keycloakUserId = keycloakUserId
            )

            val savedAuthUser = r2dbcEntityTemplate.insert(authUser).awaitSingle()
            logger.info("Created AuthUser with ID: ${savedAuthUser.id}")

            // Publish event for User Service to create corresponding User record
            val registrationEvent = UserRegistrationEvent(
                keycloakUserId = keycloakUserId,
                email = request.email,
                firstName = request.firstName,
                lastName = request.lastName,
                phoneNumber = request.phoneNumber
            )

            eventPublisherService.publishUserRegistrationEvent(registrationEvent)

            return savedAuthUser.toDto()

        } catch (e: Exception) {
            logger.error("Error during user registration: ${e.message}", e)
            throw e
        }
    }

    suspend fun loginUser(request: LoginRequest): LoginResponse {
        try {
            // Get user from database to verify they exist
            val authUser = authUserRepository.findByEmail(request.email)
                ?: throw IllegalArgumentException("User not found")

            // Authenticate with Keycloak and get tokens
            val tokenResponse = keycloakService.authenticateUser(request.email, request.password)

            return LoginResponse(
                accessToken = tokenResponse.accessToken,
                tokenType = "Bearer",
                expiresIn = tokenResponse.expiresIn,
                refreshToken = tokenResponse.refreshToken,
                user = authUser.toDto()
            )

        } catch (e: Exception) {
            logger.error("Error during user login: ${e.message}", e)
            throw e
        }
    }

    suspend fun getUserByEmail(email: String): AuthUserDto? {
        return authUserRepository.findByEmail(email)?.toDto()
    }

    suspend fun getUserByKeycloakId(keycloakUserId: String): AuthUserDto? {
        return authUserRepository.findByKeycloakUserId(keycloakUserId)?.toDto()
    }

    suspend fun refreshToken(refreshToken: String): TokenResponse {
        return keycloakService.refreshToken(refreshToken)
    }
} 