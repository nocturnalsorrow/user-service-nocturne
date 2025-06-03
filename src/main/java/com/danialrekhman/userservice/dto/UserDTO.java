package com.danialrekhman.userservice.dto;

import com.danialrekhman.userservice.model.Role;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UserDTO {

    String email;

    String username;

    String password;

    Role role;
}
