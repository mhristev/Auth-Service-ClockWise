package com.clockwise.authService.service

import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.util.*

@Component
class JwtUtils {
    private val logger = LoggerFactory.getLogger(JwtUtils::class.java)
    private val objectMapper = ObjectMapper()

    // Role hierarchy: ADMIN > MANAGER > EMPLOYEE
    private val roleHierarchy = mapOf(
        "admin" to 3,
        "manager" to 2,
        "employee" to 1
    )

    fun extractHighestRole(accessToken: String): String {
        try {
            // JWT tokens have 3 parts separated by dots: header.payload.signature
            val parts = accessToken.split(".")
            if (parts.size != 3) {
                logger.warn("Invalid JWT token format")
                return "EMPLOYEE" // Default fallback
            }

            // Decode the payload (second part)
            val payload = parts[1]
            val decodedBytes = Base64.getUrlDecoder().decode(payload)
            val payloadJson = String(decodedBytes)

            logger.debug("JWT Payload: $payloadJson")

            // Parse the JSON payload
            val payloadMap = objectMapper.readValue(payloadJson, Map::class.java)

            // Extract realm access roles
            val realmAccess = payloadMap["realm_access"] as? Map<*, *>
            val roles = realmAccess?.get("roles") as? List<*>

            if (roles.isNullOrEmpty()) {
                logger.warn("No roles found in JWT token")
                return "EMPLOYEE" // Default fallback
            }

            logger.info("Found roles in JWT: $roles")

            // Find the highest role based on hierarchy
            var highestRole = "employee"
            var highestRoleValue = 0

            roles.forEach { role ->
                val roleStr = role.toString().lowercase()
                val roleValue = roleHierarchy[roleStr] ?: 0
                if (roleValue > highestRoleValue) {
                    highestRoleValue = roleValue
                    highestRole = roleStr
                }
            }

            logger.info("Highest role determined: $highestRole")
            return highestRole.uppercase()

        } catch (e: Exception) {
            logger.error("Error extracting role from JWT token: ${e.message}", e)
            return "EMPLOYEE" // Default fallback
        }
    }
} 
 
 