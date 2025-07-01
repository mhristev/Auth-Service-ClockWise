package com.clockwise.authService.service

import com.clockwise.authService.event.UserRegistrationEvent
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

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
    val refreshToken: String? = null
)

@Service
class AuthService(
    private val keycloakService: KeycloakService,
    private val eventPublisherService: EventPublisherService
) {
    private val logger = LoggerFactory.getLogger(AuthService::class.java)

    @Transactional
    suspend fun registerUser(request: RegisterRequest): Map<String, String> {
        try {
            logger.info("Starting user registration for email: ${request.email}")

            // Create user in Keycloak with 'employee' role
            val keycloakUserId = keycloakService.createRegularUser(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName
            )

            logger.info("Created Keycloak user with ID: $keycloakUserId")

            // Publish event for User Service to create corresponding User record
            val registrationEvent = UserRegistrationEvent(
                keycloakUserId = keycloakUserId,
                email = request.email,
                firstName = request.firstName,
                lastName = request.lastName,
                phoneNumber = request.phoneNumber,
                role = "EMPLOYEE"
            )

            eventPublisherService.publishUserRegistrationEvent(registrationEvent)

            logger.info("Successfully published user registration event for Keycloak user: $keycloakUserId")

            return mapOf(
                "message" to "User registered successfully",
                "keycloakUserId" to keycloakUserId
            )

        } catch (e: IllegalArgumentException) {
            logger.warn("Registration failed for email: ${request.email}, reason: ${e.message}")
            throw e
        } catch (e: Exception) {
            logger.error("Error during user registration: ${e.message}", e)
            throw e
        }
    }

    suspend fun loginUser(request: LoginRequest): LoginResponse {
        try {
            logger.info("Starting login for email: ${request.email}")

            // Authenticate with Keycloak and get tokens
            val tokenResponse = keycloakService.authenticateUser(request.email, request.password)

            logger.info("Successfully authenticated user: ${request.email}")

            return LoginResponse(
                accessToken = tokenResponse.accessToken,
                tokenType = "Bearer",
                expiresIn = tokenResponse.expiresIn,
                refreshToken = tokenResponse.refreshToken
            )

        } catch (e: Exception) {
            logger.error("Error during user login: ${e.message}", e)
            throw e
        }
    }

    suspend fun refreshToken(refreshToken: String): TokenResponse {
        return keycloakService.refreshToken(refreshToken)
    }

    suspend fun createAdminUser(request: RegisterRequest): Map<String, String> {
        try {
            logger.info("Starting admin user creation for email: ${request.email}")

            // Create admin user in Keycloak with roles
            val keycloakUserId = keycloakService.createAdminUser(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName
            )

            logger.info("Created Admin Keycloak user with ID: $keycloakUserId")

            // Publish event for User Service to create corresponding User record
            val registrationEvent = UserRegistrationEvent(
                keycloakUserId = keycloakUserId,
                email = request.email,
                firstName = request.firstName,
                lastName = request.lastName,
                phoneNumber = request.phoneNumber,
                role = "ADMIN"
            )

            eventPublisherService.publishUserRegistrationEvent(registrationEvent)

            logger.info("Successfully published admin user registration event for Keycloak user: $keycloakUserId")

            return mapOf(
                "message" to "Admin user created successfully",
                "keycloakUserId" to keycloakUserId
            )

        } catch (e: Exception) {
            logger.error("Error during admin user creation: ${e.message}", e)
            throw e
        }
    }

    suspend fun createManagerUser(request: RegisterRequest): Map<String, String> {
        try {
            logger.info("Starting manager user creation for email: ${request.email}")

            // Create manager user in Keycloak with roles
            val keycloakUserId = keycloakService.createManagerUser(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName
            )

            logger.info("Created Manager Keycloak user with ID: $keycloakUserId")

            // Publish event for User Service to create corresponding User record
            val registrationEvent = UserRegistrationEvent(
                keycloakUserId = keycloakUserId,
                email = request.email,
                firstName = request.firstName,
                lastName = request.lastName,
                phoneNumber = request.phoneNumber,
                role = "MANAGER"
            )

            eventPublisherService.publishUserRegistrationEvent(registrationEvent)

            logger.info("Successfully published manager user registration event for Keycloak user: $keycloakUserId")

            return mapOf(
                "message" to "Manager user created successfully",
                "keycloakUserId" to keycloakUserId
            )

        } catch (e: Exception) {
            logger.error("Error during manager user creation: ${e.message}", e)
            throw e
        }
    }
} 