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
    public boolean signUpUser(User user) {
        // check if user exists
        if(userRepository.existsByEmail(user.getEmail())) return false;

        user.setRole(Role.ROLE_USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return true;
    }

    @Override
    public String verify(User user) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                user.getEmail(), user.getPassword()));

        if(authentication.isAuthenticated())
            return jwtService.generateToken(user.getEmail());
        else
            throw new BadCredentialsException("Wrong email or password");
    }

    @Override
    public void saveUser(User user) {
        userRepository.save(user);
    }

    @Override
    public void saveUser(User user, MultipartFile imageFile, Authentication authentication) {

        User dbUser;

        // Проверяем: если аутентификация есть — это обновление
        if (authentication != null && authentication.getName() != null) {
            dbUser = userRepository.findByEmail(authentication.getName())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // Обновляем только непустые поля
            if (user.getUsername() != null && !user.getUsername().isBlank())
                dbUser.setUsername(user.getUsername());

            if (user.getPassword() != null && !user.getPassword().isBlank())
                dbUser.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));

            // Если пришёл файл — обновляем аватар
            if (imageFile != null && !imageFile.isEmpty()) {
                try {
                    dbUser.setProfileImage(imageFile.getBytes());
                } catch (IOException e) {
                    throw new RuntimeException("Ошибка обработки файла", e);
                }
            }

        } else {

            // Создание нового пользователя — должны быть обязательные поля
            if (userRepository.existsByEmail(user.getEmail())) throw new RuntimeException("Email already in use");

            if (user.getEmail() == null || user.getEmail().isBlank()) throw new RuntimeException("Email is required");

            if (user.getUsername() == null || user.getUsername().isBlank()) throw new RuntimeException("Username is required");

            if (user.getPassword() == null || user.getPassword().isBlank()) throw new RuntimeException("Password is required");

            dbUser = new User();
            dbUser.setEmail(user.getEmail());
            dbUser.setUsername(user.getUsername());
            dbUser.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
            dbUser.setRole(user.getRole() != null ? user.getRole() : Role.ROLE_USER);
        }

        userRepository.save(dbUser);
    }

    @Override
    public void deleteUserByEmail(String email) {
        userRepository.deleteById(email);
    }
}
