package com.danialrekhman.userservice.service;

import com.danialrekhman.userservice.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface UserService {

    User signUpUser(User user);

    String verifyAndReturnToken(User user);

    User createUser(User user);

    User updateUser(User user, MultipartFile imageFile, Authentication authentication);

    boolean deleteUserByEmail(String email);

    Optional<User> getUserByEmail(String email);

    List<User> getAllUsers();
}
