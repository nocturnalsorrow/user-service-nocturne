package com.danialrekhman.userservice.controller;

import com.danialrekhman.userservice.dto.AuthResponseDTO;
import com.danialrekhman.userservice.dto.UserDTO;
import com.danialrekhman.userservice.model.User;
import com.danialrekhman.userservice.service.UserService;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {

    UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody UserDTO userDTO) {
        try {
            User user = new User();
            user.setEmail(userDTO.getEmail());
            user.setPassword(userDTO.getPassword());
            user.setUsername(userDTO.getUsername());

            User savedUser = userService.signUpUser(user);

            return ResponseEntity.ok("User registered successfully with email: " + savedUser.getEmail());

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Unexpected error: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@RequestBody UserDTO userDTO) {

        User user = new User();
        user.setEmail(userDTO.getEmail());
        user.setPassword(userDTO.getPassword());

        String token = userService.verifyAndReturnToken(user);
        return ResponseEntity.ok(new AuthResponseDTO(token));
    }

    @GetMapping
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }

    @GetMapping("/{email}")
    public ResponseEntity<User> getUserByEmail(@PathVariable String email) {
        return userService.getUserByEmail(email)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/me")
    public ResponseEntity<User> getCurrentUser(Authentication authentication) {
        String email = authentication.getName();
        return userService.getUserByEmail(email)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/update")
    public ResponseEntity<String> updateUser(
            @ModelAttribute User user,
            @RequestParam(value = "imageFile", required = false) MultipartFile imageFile,
            Authentication authentication
    ) {
        userService.updateUser(user, imageFile, authentication);
        return ResponseEntity.ok("User successfully updated");
    }

    @DeleteMapping("/{email}")
    public ResponseEntity<String> deleteUser(@PathVariable String email) {
        if (!userService.deleteUserByEmail(email))
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User with email '" + email + "' not found");
        return ResponseEntity.ok("User with email '" + email + "' was successfully deleted");
    }
}
