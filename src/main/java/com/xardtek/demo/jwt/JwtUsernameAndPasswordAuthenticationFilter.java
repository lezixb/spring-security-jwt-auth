package com.xardtek.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;
import java.util.jar.JarException;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final org.slf4j.Logger log = LoggerFactory.getLogger(this.getClass());

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;
    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(JwtConfig jwtConfig, SecretKey secretKey, AuthenticationManager authenticationManager) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );
            log.info("=================================================================================");
            log.info("PRE-AUTHENTICATION:: User MUST PASS initial Checks to see POST-AUTHENTICATION!!");
            log.info("=================================================================================");
            log.info("username:::" + authentication.getPrincipal());
            log.info("isAuthentication:::" + authentication.isAuthenticated());
            Authentication authenticate = authenticationManager.authenticate(authentication);
            log.info("=================================");
            log.info("POST-AUTHENTICATION::: Passed initial checks!!");
            log.info("=================================");
            log.info("username:::" + authenticate.getName());
            log.info("Authenticated:::" + authenticate.isAuthenticated());
            Object principal = authenticate.getPrincipal();
            if (principal instanceof UserDetails && authenticate.isAuthenticated()) {
                log.info("isAccountNonExpired:::" + ((UserDetails) principal).isAccountNonExpired());
                log.info("isAccountNonLocked:::" + ((UserDetails) principal).isAccountNonLocked());
                log.info("isEnabled:::" + ((UserDetails) principal).isEnabled());
            }
            log.info("Authenticated Token Sent::::" + authenticate.isAuthenticated());
            log.info("GrantedAuthorities:::" + authenticate.getAuthorities());
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException();
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        try {
            String token = Jwts.builder()
                    .setSubject(authResult.getName())
                    .claim("authorities", authResult.getAuthorities())
                    .setIssuedAt(new Date())
                    .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpireAfterDays())))
                    // .signWith(Keys.hmacShaKeyFor(key.getBytes())).compact();
                    .signWith(secretKey).compact();
            response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token); //Response Header Sent to Client !!

            log.info(jwtConfig.getAuthorizationHeader() + " ::: Token " + jwtConfig.getTokenPrefix() + token); //TODO - 4 Take out this line of code in Production
            log.info("ExpireAfterDays:::" + jwtConfig.getTokenExpireAfterDays());
            log.info("=================================================================================");
        } catch (JwtException ex) {
            throw new JarException();
            //don't trust the JWT!
        }
    }

}
