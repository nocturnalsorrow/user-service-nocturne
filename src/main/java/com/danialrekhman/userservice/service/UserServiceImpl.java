package com.danialrekhman.userservice.service;

import com.danialrekhman.userservice.model.Role;
import com.danialrekhman.userservice.model.User;
import com.danialrekhman.userservice.repository.UserRepository;
import com.danialrekhman.userservice.security.JwtService;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserServiceImpl implements UserService {

    UserRepository userRepository;

    AuthenticationManager authenticationManager;

    PasswordEncoder passwordEncoder;

    JwtService jwtService;

    public UserServiceImpl(UserRepository userRepository, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User signUpUser(User user) {
        if (userRepository.existsByEmail(user.getEmail()))
            throw new IllegalArgumentException("User with this email already exists");

        user.setRole(Role.ROLE_USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public String verifyAndReturnToken(User user) {
        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                user.getEmail(), user.getPassword()));

        if (authentication.isAuthenticated()) {
            User fullUser = userRepository.findByEmail(user.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            return jwtService.generateToken(fullUser.getEmail(), fullUser.getRole().name());
        } else
            throw new BadCredentialsException("Wrong email or password");
    }

    @Override
    public User createUser(User user) {

        if (userRepository.existsByEmail(user.getEmail()))
            throw new IllegalArgumentException("Email already in use");

        if (user.getEmail() == null || user.getEmail().isBlank())
            throw new IllegalArgumentException("Email is required");

        if (user.getUsername() == null || user.getUsername().isBlank())
            throw new IllegalArgumentException("Username is required");

        if (user.getPassword() == null || user.getPassword().isBlank())
            throw new IllegalArgumentException("Password is required");

        User newUser = new User();
        newUser.setEmail(user.getEmail());
        newUser.setUsername(user.getUsername());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));
        newUser.setRole(user.getRole() != null ? user.getRole() : Role.ROLE_USER);

        return userRepository.save(newUser);
    }

    @Override
    public User updateUser(User user, MultipartFile imageFile, Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            throw new SecurityException("Unauthorized to update user");
        }

        User dbUser = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user.getUsername() != null && !user.getUsername().isBlank())
            dbUser.setUsername(user.getUsername());

        if (user.getPassword() != null && !user.getPassword().isBlank())
            dbUser.setPassword(passwordEncoder.encode(user.getPassword()));

        if (imageFile != null && !imageFile.isEmpty()) {
            try {
                dbUser.setProfileImage(imageFile.getBytes());
            } catch (IOException e) {
                throw new RuntimeException("Failed to process image file", e);
            }
        }

        return userRepository.save(dbUser);
    }

    @Override
    public boolean deleteUserByEmail(String email) {
        if (!userRepository.existsById(email)) return false;
        userRepository.deleteById(email);
        return true;
    }
}