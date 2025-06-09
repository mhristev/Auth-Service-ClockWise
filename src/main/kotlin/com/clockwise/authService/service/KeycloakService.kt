package com.clockwise.authService.service

import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.KeycloakBuilder
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.UserRepresentation
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.http.MediaType
import kotlinx.coroutines.reactor.awaitSingle
import jakarta.ws.rs.core.Response

@Service
class KeycloakService {
    private val logger = LoggerFactory.getLogger(KeycloakService::class.java)

    @Value("\${keycloak.server-url}")
    private lateinit var serverUrl: String

    @Value("\${keycloak.realm}")
    private lateinit var realm: String

    @Value("\${keycloak.admin.client-id}")
    private lateinit var adminClientId: String

    @Value("\${keycloak.admin.username}")
    private lateinit var adminUsername: String

    @Value("\${keycloak.admin.password}")
    private lateinit var adminPassword: String

    private val webClient = WebClient.builder().build()

    private fun getKeycloakInstance(): Keycloak {
        return KeycloakBuilder.builder()
            .serverUrl(serverUrl)
            .realm("master")
            .clientId(adminClientId)
            .username(adminUsername)
            .password(adminPassword)
            .build()
    }

    suspend fun authenticateUser(email: String, password: String): TokenResponse {
        try {
            val tokenUrl = "$serverUrl/realms/$realm/protocol/openid-connect/token"
            
            val formData = LinkedMultiValueMap<String, String>().apply {
                add("grant_type", "password")
                add("client_id", "auth-service")
                add("client_secret", "v8Sac9YQKLm0ZrGiS9JgwLRMa4Q0pF7c")
                add("username", email)
                add("password", password)
            }

            val response = webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(formData)
                .retrieve()
                .bodyToMono(Map::class.java)
                .awaitSingle()

            @Suppress("UNCHECKED_CAST")
            val responseMap = response as Map<String, Any>

            return TokenResponse(
                accessToken = responseMap["access_token"] as String,
                tokenType = responseMap["token_type"] as String? ?: "Bearer",
                expiresIn = responseMap["expires_in"] as Int,
                refreshToken = responseMap["refresh_token"] as String?
            )

        } catch (e: Exception) {
            logger.error("Error authenticating user: ${e.message}", e)
            throw IllegalArgumentException("Invalid credentials")
        }
    }

    suspend fun createUser(email: String, password: String, firstName: String, lastName: String): String {
        val keycloak = getKeycloakInstance()
        
        try {
            val user = UserRepresentation().apply {
                this.email = email
                this.username = email
                this.firstName = firstName
                this.lastName = lastName
                isEnabled = true
                isEmailVerified = false
            }

            val credential = CredentialRepresentation().apply {
                type = CredentialRepresentation.PASSWORD
                value = password
                isTemporary = false
            }

            user.credentials = listOf(credential)

            val response: Response = keycloak.realm(realm).users().create(user)
            
            return when (response.status) {
                201 -> {
                    val location = response.location.path
                    val userId = location.substring(location.lastIndexOf('/') + 1)
                    logger.info("Successfully created Keycloak user with ID: $userId")
                    userId
                }
                409 -> {
                    logger.warn("User already exists in Keycloak: $email")
                    throw IllegalArgumentException("User already exists")
                }
                else -> {
                    logger.error("Failed to create Keycloak user. Status: ${response.status}")
                    throw RuntimeException("Failed to create user in Keycloak")
                }
            }
        } catch (e: Exception) {
            logger.error("Error creating user in Keycloak: ${e.message}", e)
            throw e
        } finally {
            keycloak.close()
        }
    }

    suspend fun deleteUser(keycloakUserId: String) {
        val keycloak = getKeycloakInstance()
        
        try {
            val response = keycloak.realm(realm).users().delete(keycloakUserId)
            if (response.status == 204) {
                logger.info("Successfully deleted Keycloak user with ID: $keycloakUserId")
            } else {
                logger.error("Failed to delete Keycloak user. Status: ${response.status}")
                throw RuntimeException("Failed to delete user from Keycloak")
            }
        } catch (e: Exception) {
            logger.error("Error deleting user from Keycloak: ${e.message}", e)
            throw e
        } finally {
            keycloak.close()
        }
    }

    suspend fun refreshToken(refreshToken: String): TokenResponse {
        try {
            val tokenUrl = "$serverUrl/realms/$realm/protocol/openid-connect/token"
            
            val formData = LinkedMultiValueMap<String, String>().apply {
                add("grant_type", "refresh_token")
                add("client_id", "auth-service")
                add("client_secret", "v8Sac9YQKLm0ZrGiS9JgwLRMa4Q0pF7c")
                add("refresh_token", refreshToken)
            }

            val response = webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(formData)
                .retrieve()
                .bodyToMono(Map::class.java)
                .awaitSingle()

            @Suppress("UNCHECKED_CAST")
            val responseMap = response as Map<String, Any>

            return TokenResponse(
                accessToken = responseMap["access_token"] as String,
                tokenType = responseMap["token_type"] as String? ?: "Bearer",
                expiresIn = responseMap["expires_in"] as Int,
                refreshToken = responseMap["refresh_token"] as String?
            )

        } catch (e: Exception) {
            logger.error("Error refreshing token: ${e.message}", e)
            throw IllegalArgumentException("Invalid refresh token")
        }
    }
} 