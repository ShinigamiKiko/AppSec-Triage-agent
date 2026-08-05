---
id: spring
version: "1.0"
name: Spring Boot (Java / Kotlin)
detect:
  files: ["pom.xml", "build.gradle", "build.gradle.kts"]
  contains:
    - "spring-boot-starter"
    - "org.springframework.boot"
---
**Configuration placeholders.** `${DB_PASSWORD}` in `application.yml` / `application.properties` is
resolved from the environment or a config server. The literal is a reference, not a secret. A value
written inline with no `${}` is a real committed value — judge it on entropy and context.

**Profiles.** `application-dev.yml` and `application-test.yml` hold development values by
convention; `application-prod.yml` does not. The filename is evidence about intent.

**JPA / JDBC.** `?` positional and `:name` named parameters are bound. `@Query` with SpEL or string
concatenation, `EntityManager.createNativeQuery` with an interpolated string, and
`JdbcTemplate.query` built by `+` are the injectable forms. Sort direction and column names cannot be
bound and are the usual real finding.

**Request input.** `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`,
`@CookieValue`, `HttpServletRequest.getParameter`. A `@Valid` annotated DTO was validated for shape,
which is not the same as being safe.

**Templating.** Thymeleaf `th:text` escapes; `th:utext` does not. JSP `<c:out>` escapes; `${...}`
written straight into the page does not.

**Security.** `@PreAuthorize`, `@Secured` and the `SecurityFilterChain` govern access. Check the
filter chain before asserting an endpoint is unauthenticated — a permitAll on `/api/**` is a
finding, a missing annotation under an authenticated matcher is not.

**Crypto.** `SecureRandom` is correct; `new Random()` is not, when the value guards something.
`BCryptPasswordEncoder` / `Argon2PasswordEncoder` are correct for passwords; `MessageDigest` is not.
