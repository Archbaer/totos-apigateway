package com.totos.apigateway.filter;

import com.totos.apigateway.service.PublicKeyService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.core.Ordered;
import org.springframework.web.server.WebFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.security.PublicKey;
import java.security.SignatureException;
import java.util.List;

@Component
public class JwtAuthFilter implements WebFilter, Ordered {

    private PublicKey publicKey;

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

        // Skip authentication for login and registration endpoints
        if (path.contains("/auth/login") || path.contains("/auth/register") || path.startsWith("/auth/test")) {
            return chain.filter(exchange);
        }

        // Get JWT from authorization header
        List<String> authHeaders = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            return unauthorizedResponse(exchange);
        }
        System.out.println(authHeaders);
        String token = authHeaders.get(0).replace("Bearer ", "");

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKeyService.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // valid token continue the exchange
            return chain.filter(exchange);

        } catch (SignatureException e) {
            return unauthorizedResponse(exchange);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }



    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
