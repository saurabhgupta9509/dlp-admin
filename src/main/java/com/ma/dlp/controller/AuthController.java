package com.ma.dlp.controller;

import com.ma.dlp.dto.ApiResponse;
import com.ma.dlp.model.User;
import com.ma.dlp.service.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Admin Login
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest request, HttpSession session) {
        try {
            // Validate admin user
            Optional<User> userOpt = userService.findByUsername(request.getUsername());

            if (userOpt.isEmpty() || !passwordEncoder.matches(request.getPassword() , userOpt.get().getPassword())) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse<>(false, "Invalid username or password"));
            }

            User user = userOpt.get();

//            // Check password
//            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
//                return ResponseEntity.badRequest()
//                        .body(new ApiResponse<>(false, "Invalid username or password"));
//            }

            // Check if user is admin
            if (user.getRole() != User.UserRole.ADMIN) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse<>(false, "Admin access required"));
            }
            List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                    new SimpleGrantedAuthority(user.getRole().name())
            );

            // 2. Create an authentication token for Spring Security.
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user.getUsername(), null, authorities
            );

            // 3. Set this token in Spring Security's context.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // recognizes the user on subsequent requests (prevents 403).
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    SecurityContextHolder.getContext()
            );

            // Update last login
            user.setLastLogin(new Date());
            userService.save(user);

            // Create session
            session.setAttribute("currentUser", user);
            session.setMaxInactiveInterval(30 * 60); // 30 minutes

            // Create response
            LoginResponse response = new LoginResponse(
                    user.getId(),
                    user.getUsername(),
                    user.getRole().toString(),
                    "Login successful"
            );

            return ResponseEntity.ok(new ApiResponse<>(true, "Login successful", response));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Login failed: " + e.getMessage()));
        }
    }

    // Logout
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpSession session) {
        session.invalidate();
        SecurityContextHolder.clearContext();  //clear the security context
        return ResponseEntity.ok(new ApiResponse<>(true, "Logout successful"));
    }

    // Check auth status
    @GetMapping("/check")
    public ResponseEntity<ApiResponse<LoginResponse>> checkAuth(HttpSession session) {
        User currentUser = (User) session.getAttribute("currentUser");

        if (currentUser == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Not authenticated"));
        }

        LoginResponse response = new LoginResponse(
                currentUser.getId(),
                currentUser.getUsername(),
                currentUser.getRole().toString(),
                "Authenticated"
        );

        return ResponseEntity.ok(new ApiResponse<>(true, "Authenticated", response));
    }

    // Register new user (admin/agent)
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<User>> register(@RequestBody RegisterRequest request) {
        try {
            // Check if username exists
            if (userService.findByUsername(request.getUsername()).isPresent()) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse<>(false, "Username already exists"));
            }

            // Create user
            User user = new User();
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRole(User.UserRole.valueOf(request.getRole().toUpperCase()));
            user.setStatus(User.UserStatus.ACTIVE);

            User savedUser = userService.save(user);

            return ResponseEntity.ok(new ApiResponse<>(true, "User created successfully", savedUser));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Registration failed: " + e.getMessage()));
        }
    }

    // DTO Classes
    @Data
    public static class LoginRequest {
        private String username;
        private String password;

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }
    }

    @Data
    public static class RegisterRequest {
        private String username;
        private String password;
        private String role; // ADMIN, AGENT

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }

    @Data
    public static class LoginResponse {
        private Long userId;
        private String username;
        private String role;
        private String message;

        public LoginResponse(Long userId, String username, String role, String message) {
            this.userId = userId;
            this.username = username;
            this.role = role;
            this.message = message;


        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public Long getUserId() {
            return userId;
        }

        public void setUserId(Long userId) {
            this.userId = userId;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public UserService getUserService() {
        return userService;
    }

    public void setUserService(UserService userService) {
        this.userService = userService;
    }
}