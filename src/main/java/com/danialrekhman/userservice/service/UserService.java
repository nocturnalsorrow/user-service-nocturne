package com.danialrekhman.userservice.service;

import com.danialrekhman.userservice.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface UserService {

    List<User> getAllUsers();

    Optional<User> getUserByEmail(String email);

    boolean signUpUser(User user);

    String verify(User user);

    void saveUser(User user);

    void saveUser(User user, MultipartFile imageFile, Authentication authentication);

    void deleteUserByEmail(String email);


}
