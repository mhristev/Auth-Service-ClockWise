package com.clockwise.authService.controller

import com.clockwise.authService.service.AuthService
import com.clockwise.authService.service.AuthUserDto
import com.clockwise.authService.service.RegisterRequest
import com.clockwise.authService.service.LoginRequest
import com.clockwise.authService.service.LoginResponse
import com.clockwise.authService.service.RefreshTokenRequest
import com.clockwise.authService.service.TokenResponse
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

data class ErrorResponse(
    val status: Int,
    val error: String,
    val message: String,
    val path: String
)

@RestController
@RequestMapping("/v1/auth")
class AuthController(
    private val authService: AuthService
) {
    private val logger = LoggerFactory.getLogger(AuthController::class.java)

    @PostMapping("/authenticate")
    suspend fun authenticate(@RequestBody request: LoginRequest): ResponseEntity<Any> {
        return try {
            logger.info("Login attempt for email: ${request.email}")
            val loginResponse = authService.loginUser(request)
            logger.info("Login successful for email: ${request.email}")
            ResponseEntity.ok(loginResponse)
        } catch (e: IllegalArgumentException) {
            logger.warn("Login failed for email: ${request.email}, reason: ${e.message}")
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ErrorResponse(
                    status = HttpStatus.UNAUTHORIZED.value(),
                    error = "Unauthorized",
                    message = e.message ?: "Invalid credentials",
                    path = "/v1/auth/authenticate"
                )
            )
        } catch (e: Exception) {
            logger.error("Login error for email: ${request.email}", e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ErrorResponse(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    error = "Internal Server Error",
                    message = "An unexpected error occurred during login",
                    path = "/v1/auth/authenticate"
                )
            )
        }
    }

    @PostMapping("/register")
    public suspend fun register(@RequestBody request: RegisterRequest): ResponseEntity<Any> {
        return try {
            logger.info("Registration attempt for email: ${request.email}")
            val authUser = authService.registerUser(request)
            logger.info("Registration successful for email: ${request.email}")
            ResponseEntity.status(HttpStatus.CREATED).body(authUser)
        } catch (e: IllegalArgumentException) {
            logger.warn("Registration failed for email: ${request.email}, reason: ${e.message}")
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ErrorResponse(
                    status = HttpStatus.BAD_REQUEST.value(),
                    error = "Bad Request",
                    message = e.message ?: "Registration failed",
                    path = "/v1/auth/register"
                )
            )
        } catch (e: Exception) {
            logger.error("Registration error for email: ${request.email}", e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ErrorResponse(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    error = "Internal Server Error",
                    message = "An unexpected error occurred during registration",
                    path = "/v1/auth/register"
                )
            )
        }
    }

    @PostMapping("/login")
    suspend fun login(@RequestBody request: LoginRequest): ResponseEntity<Any> {
        return try {
            logger.info("Login attempt for email: ${request.email}")
            val loginResponse = authService.loginUser(request)
            logger.info("Login successful for email: ${request.email}")
            ResponseEntity.ok(loginResponse)
        } catch (e: IllegalArgumentException) {
            logger.warn("Login failed for email: ${request.email}, reason: ${e.message}")
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ErrorResponse(
                    status = HttpStatus.UNAUTHORIZED.value(),
                    error = "Unauthorized",
                    message = e.message ?: "Invalid credentials",
                    path = "/v1/auth/login"
                )
            )
        } catch (e: Exception) {
            logger.error("Login error for email: ${request.email}", e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ErrorResponse(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    error = "Internal Server Error",
                    message = "An unexpected error occurred during login",
                    path = "/v1/auth/login"
                )
            )
        }
    }

    @GetMapping("/user/{keycloakUserId}")
    suspend fun getUserByKeycloakId(@PathVariable keycloakUserId: String): ResponseEntity<AuthUserDto> {
        val authUser = authService.getUserByKeycloakId(keycloakUserId)
        return if (authUser != null) {
            ResponseEntity.ok(authUser)
        } else {
            ResponseEntity.notFound().build()
        }
    }

    @GetMapping("/user/email/{email}")
    suspend fun getUserByEmail(@PathVariable email: String): ResponseEntity<AuthUserDto> {
        val authUser = authService.getUserByEmail(email)
        return if (authUser != null) {
            ResponseEntity.ok(authUser)
        } else {
            ResponseEntity.notFound().build()
        }
    }

    @PostMapping("/refresh")
    suspend fun refreshToken(@RequestBody refreshRequest: RefreshTokenRequest): ResponseEntity<TokenResponse> {
        return try {
            val tokenResponse = authService.refreshToken(refreshRequest.refreshToken)
            ResponseEntity.ok(tokenResponse)
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        }
    }

    @PostMapping("/create-manager")
    suspend fun createManager(@RequestBody request: RegisterRequest): ResponseEntity<Any> {
        return try {
            logger.info("Manager creation attempt for email: ${request.email}")
            val authUser = authService.createManagerUser(request)
            logger.info("Manager creation successful for email: ${request.email}")
            ResponseEntity.status(HttpStatus.CREATED).body(authUser)
        } catch (e: IllegalArgumentException) {
            logger.warn("Manager creation failed for email: ${request.email}, reason: ${e.message}")
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ErrorResponse(
                    status = HttpStatus.BAD_REQUEST.value(),
                    error = "Bad Request",
                    message = e.message ?: "Manager creation failed",
                    path = "/v1/auth/create-manager"
                )
            )
        } catch (e: Exception) {
            logger.error("Manager creation error for email: ${request.email}", e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ErrorResponse(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    error = "Internal Server Error",
                    message = "An unexpected error occurred during manager creation",
                    path = "/v1/auth/create-manager"
                )
            )
        }
    }

    @PostMapping("/create-admin")
    suspend fun createAdmin(@RequestBody request: RegisterRequest): ResponseEntity<Any> {
        return try {
            logger.info("Admin creation attempt for email: ${request.email}")
            val authUser = authService.createAdminUser(request)
            logger.info("Admin creation successful for email: ${request.email}")
            ResponseEntity.status(HttpStatus.CREATED).body(authUser)
        } catch (e: IllegalArgumentException) {
            logger.warn("Admin creation failed for email: ${request.email}, reason: ${e.message}")
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ErrorResponse(
                    status = HttpStatus.BAD_REQUEST.value(),
                    error = "Bad Request",
                    message = e.message ?: "Admin creation failed",
                    path = "/v1/auth/create-admin"
                )
            )
        } catch (e: Exception) {
            logger.error("Admin creation error for email: ${request.email}", e)
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ErrorResponse(
                    status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    error = "Internal Server Error",
                    message = "An unexpected error occurred during admin creation",
                    path = "/v1/auth/create-admin"
                )
            )
        }
    }
} 