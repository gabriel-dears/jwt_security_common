# jwt_security_common

Shared Spring Security/JWT module used by all services in the hospital_app monorepo to configure OAuth2 Resource Server (JWT) consistently.

It provides:
- A JwtDecoder wired to an RSA public key (classpath:public.key) to validate tokens.
- A JwtAuthenticationConverter that maps the claim "role" to a Spring authority in the form ROLE_<ROLE>.
- A Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> bean you can inject into service SecurityFilterChain to enable JWT auth with a single line.
- Utility class KeyHandler to parse PEM-encoded RSA keys (public/private) from Spring Resource.


## When to use
Include this module in any service that should accept and validate JWTs issued by the User Service (or any issuer using the same RSA key pair and claims).

Services currently using it:
- user_service (as resource server for most endpoints; also issues JWTs using its private key)
- appointment_service (resource server)
- appointment_history_service (resource server)


## How it works
- The module expects an RSA public key at classpath:public.key. This key is used to verify RS256-signed tokens.
- The JwtAuthenticationConverter reads the claim role and grants authority ROLE_<role>. Example: claim { "role": "ADMIN" } becomes authority ROLE_ADMIN.
- The CommonJwtSecurityConfig exposes a Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> bean so services can plug it into their HttpSecurity configuration.

Relevant classes:
- infra/config/CommonJwtSecurityConfig.java
- application/KeyHandler.java
- src/main/resources/application.yml (sets spring.security.oauth2.resourceserver.jwt.public-key-location=classpath:public.key)


## Adding to a service
1) Add dependency in the service's pom.xml:

    <dependency>
      <groupId>com.hospital_app</groupId>
      <artifactId>jwt_security_common</artifactId>
      <version>0.0.1-SNAPSHOT</version>
    </dependency>

2) Inject and apply the OAuth2 customizer in your SecurityFilterChain:

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oAuth2Customizer) throws Exception {
        http
          .csrf(AbstractHttpConfigurer::disable)
          .authorizeHttpRequests(auth -> auth
            .requestMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**").permitAll()
            // ... your endpoint rules
            .anyRequest().authenticated()
          )
          .oauth2ResourceServer(oAuth2Customizer) // Provided by jwt_security_common
          .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

This matches how appointment_service and user_service are already configured.

3) Ensure the public key is available at runtime as classpath:public.key.
- During local development: put the file at src/main/resources/public.key in the service or rely on the module’s classpath if you place it under jwt_security_common/src/main/resources/.
- In Docker images: resources are packaged into the JAR by Maven; as long as public.key is present in classpath resources, it will be available.


## Generating keys
Use the provided helper script to generate a compatible key pair (private key for user_service, public key for jwt_security_common):

- Script: scripts/JWT_keys_generator.sh
- It generates:
  - user_service/src/main/resources/private.key (PKCS#8 PEM) used to sign JWTs
  - jwt_security_common/src/main/resources/public.key used by resource servers to verify JWTs

Example run:

    cd scripts
    bash JWT_keys_generator.sh

After generation, rebuild the monorepo:

    mvn -q -DskipTests clean package


## JWT claims convention
Tokens issued by user_service include at least:
- sub: username (subject)
- role: one of ADMIN, DOCTOR, NURSE, PATIENT (mapped to ROLE_<ROLE>)
- user_id: UUID of the user (services can read this to scope queries; see appointment_history_service GraphQL controller)
- iat/exp: standard timestamps

If you need to change the claim used for authorities, update CommonJwtSecurityConfig.jwtAuthenticationConverter().


## Configuration
Default configuration (from this module):
- spring.security.oauth2.resourceserver.jwt.public-key-location=classpath:public.key

No additional environment variables are required. Just ensure the public key is present.


## Troubleshooting
- 401 Unauthorized: ensure Authorization: Bearer <token> is provided and the token is signed with the matching private key.
- 403 Forbidden: token is valid but lacks required role; verify the role claim and your endpoint rules use hasRole/hasAnyRole with the expected names.
- Public key not found: make sure public.key is on the classpath. If you moved keys, adjust spring.security.oauth2.resourceserver.jwt.public-key-location.
- Signature or decoding errors: verify that the public.key matches the private.key used to sign tokens. Regenerate with scripts/JWT_keys_generator.sh if needed.


## Project paths and references
- Module POM: jwt_security_common/pom.xml
- Config class: jwt_security_common/src/main/java/com/hospital_app/jwt_security_common/infra/config/CommonJwtSecurityConfig.java
- Key utilities: jwt_security_common/src/main/java/com/hospital_app/jwt_security_common/application/KeyHandler.java
- Default config: jwt_security_common/src/main/resources/application.yml
- Key generation script: scripts/JWT_keys_generator.sh


## License
This project is part of an educational/portfolio repository. See root-level LICENSE if available.