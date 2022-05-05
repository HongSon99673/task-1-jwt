package com.example.demo.service;

import com.example.demo.model.ERole;
import com.example.demo.model.Role;

import java.util.Optional;

public interface IRoleService {
    Optional<Role> findByName(ERole name);
}
