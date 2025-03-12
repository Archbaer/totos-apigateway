package com.totos.apigateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class PublicKeyService {

    @Value("${auth.login-url}")
    private String LOGIN_ENDPOINT;

    @Value("${auth.public-key-url}")
    private String PUBLIC_KEY_ENDPOINT;

    private PublicKey cachedPublicKey = null;
    private String cachedToken = null;

    public PublicKey getPublicKey() throws Exception {
        // If public key is not cached, fetch it
        if (cachedPublicKey == null) {
            cachedPublicKey = fetchPublicKey();
        }
        return cachedPublicKey;
    }

    private String getLoginToken() throws Exception {
        RestTemplate restTemplate = new RestTemplate();

        // Prepare login request body
        Map<String, String> loginRequest = new HashMap<>();
        loginRequest.put("username", "api1");
        loginRequest.put("password", "123api");

        // Prepare headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Create HTTP entity with login credentials
        HttpEntity<Map<String, String>> entity = new HttpEntity<>(loginRequest, headers);

        // Make POST request to log in endpoint
        ResponseEntity<Map> response = restTemplate.exchange(
                LOGIN_ENDPOINT,
                HttpMethod.POST,
                entity,
                Map.class
        );

        // Extract JWT token from response
        return (String) response.getBody().get("token");
    }

    private PublicKey fetchPublicKey() throws Exception {
        // First, get the login token
        String apiToken = getLoginToken();
        String token = apiToken.substring(7);
        RestTemplate restTemplate = new RestTemplate();

        // Prepare headers with the API token
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        // Make GET request to public key endpoint
        ResponseEntity<String> response = restTemplate.exchange(
                PUBLIC_KEY_ENDPOINT,
                HttpMethod.GET,
                entity,
                String.class
        );

        // Directly use the public key from the response body
        String publicKeyString = response.getBody();

        // Decode Base64
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);

        // Create PublicKey object
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}