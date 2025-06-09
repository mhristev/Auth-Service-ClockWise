package com.clockwise.authService.service

import com.clockwise.authService.event.UserRegistrationEvent
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.stereotype.Service

@Service
class EventPublisherService(
    private val kafkaTemplate: KafkaTemplate<String, String>,
    private val objectMapper: ObjectMapper
) {
    private val logger = LoggerFactory.getLogger(EventPublisherService::class.java)

    @Value("\${kafka.topic.user-registration}")
    private lateinit var userRegistrationTopic: String

    suspend fun publishUserRegistrationEvent(event: UserRegistrationEvent) {
        try {
            val message = objectMapper.writeValueAsString(event)
            logger.info("Publishing user registration event for user: ${event.keycloakUserId}")
            kafkaTemplate.send(userRegistrationTopic, event.keycloakUserId, message)
            logger.info("Successfully published user registration event")
        } catch (e: Exception) {
            logger.error("Error publishing user registration event for user: ${event.keycloakUserId}", e)
            throw e
        }
    }
} 