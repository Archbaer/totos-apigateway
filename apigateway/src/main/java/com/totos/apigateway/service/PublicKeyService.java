package com.totos.apigateway.service;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class PublicKeyService {

    @Value("${auth.public-key-url}")
    private String PUBLIC_KEY_ENDPOINT;

    private final RestTemplate restTemplate = new RestTemplate();

    public PublicKey getPublicKey() {
        // Fetch the public key from the Auth API (no auth needed)
        String keyString = restTemplate.getForObject(PUBLIC_KEY_ENDPOINT, String.class);
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse public key", e);
        }
    }
}