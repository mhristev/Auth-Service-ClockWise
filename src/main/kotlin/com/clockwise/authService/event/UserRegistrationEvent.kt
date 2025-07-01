package com.clockwise.authService.event

/**
 * Event published when a user registers in Auth Service
 * This will be consumed by User Service to create corresponding User record
 */
data class UserRegistrationEvent(
    val keycloakUserId: String,  // This will be used as User.id in User Service
    val email: String,
    val firstName: String,
    val lastName: String,
    val phoneNumber: String? = null,
    val role: String = "EMPLOYEE", // Role information (ADMIN, MANAGER, EMPLOYEE)
    val timestamp: Long = System.currentTimeMillis()
) 