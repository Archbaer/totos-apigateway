package com.totos.apigateway.filter;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.totos.apigateway.service.PublicKeyService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements WebFilter, Ordered {

    @Autowired
    private PublicKeyService publicKeyService;

    @PostConstruct
    public void init() {
        System.out.println("✅ JwtAuthFilter initialized");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        System.out.println("Incoming request to: " + path);

        // Skip authentication for public endpoints
        if (path.contains("/auth/login") || path.contains("/auth/register") ||
            path.startsWith("/auth/test") || path.contains("/auth/public-key")) {
            return chain.filter(exchange);
        }

        // Get JWT from authorization header
        List<String> authHeaders = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            return unauthorizedResponse(exchange);
        }

        String token = authHeaders.get(0).replace("Bearer ", "");

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKeyService.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return chain.filter(exchange);

        } catch (io.jsonwebtoken.JwtException e) {
            // This catches all JWT-related exceptions
            return unauthorizedResponse(exchange);
        } catch (Exception e) {
            return Mono.error(e);
        }
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
