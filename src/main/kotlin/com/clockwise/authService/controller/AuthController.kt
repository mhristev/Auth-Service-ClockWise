package com.clockwise.authService.controller

import com.clockwise.authService.service.AuthService
import com.clockwise.authService.service.RegisterRequest
import com.clockwise.authService.service.LoginRequest
import com.clockwise.authService.service.LoginResponse
import com.clockwise.authService.service.RefreshTokenRequest
import com.clockwise.authService.service.TokenResponse
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import mu.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

data class ErrorResponse(
    val status: Int,
    val error: String,
    val message: String,
    val path: String
)

private val logger = KotlinLogging.logger {}

@RestController
@RequestMapping("/v1/auth")
class AuthController(
    private val authService: AuthService
) {

    // @PostMapping("/authenticate")
    // suspend fun authenticate(@RequestBody request: LoginRequest): ResponseEntity<LoginResponse> = coroutineScope {
    //     logger.info { "Login attempt for email: ${request.email}" }
    //     val loginResponse = async { authService.loginUser(request) }
    //     logger.info { "Login successful for email: ${request.email}" }
    //     ResponseEntity.ok(loginResponse.await())
    // }

    @PostMapping("/register")
    suspend fun register(@RequestBody request: RegisterRequest): ResponseEntity<Any> = coroutineScope {
        logger.info { "Registration attempt for email: ${request.email}" }
        val registrationResult = async { authService.registerUser(request) }
        logger.info { "Registration successful for email: ${request.email}" }
        ResponseEntity.status(HttpStatus.CREATED).body(registrationResult.await())
    }

    @PostMapping("/login")
    suspend fun login(@RequestBody request: LoginRequest): ResponseEntity<LoginResponse> = coroutineScope {
        logger.info { "Login attempt for email: ${request.email}" }
        val loginResponse = async { authService.loginUser(request) }
        logger.info { "Login successful for email: ${request.email}" }
        ResponseEntity.ok(loginResponse.await())
    }

    @PostMapping("/refresh")
    suspend fun refreshToken(@RequestBody refreshRequest: RefreshTokenRequest): ResponseEntity<TokenResponse> = coroutineScope {
        val tokenResponse = async { authService.refreshToken(refreshRequest.refreshToken) }
        ResponseEntity.ok(tokenResponse.await())
    }

    @PostMapping("/create-manager")
    suspend fun createManager(@RequestBody request: RegisterRequest): ResponseEntity<Any> = coroutineScope {
        logger.info { "Manager creation attempt for email: ${request.email}" }
        val managerResult = async { authService.createManagerUser(request) }
        logger.info { "Manager creation successful for email: ${request.email}" }
        ResponseEntity.status(HttpStatus.CREATED).body(managerResult.await())
    }

    @PostMapping("/create-admin")
    suspend fun createAdmin(@RequestBody request: RegisterRequest): ResponseEntity<Any> = coroutineScope {
        logger.info { "Admin creation attempt for email: ${request.email}" }
        val adminResult = async { authService.createAdminUser(request) }
        logger.info { "Admin creation successful for email: ${request.email}" }
        ResponseEntity.status(HttpStatus.CREATED).body(adminResult.await())
    }
} 