package com.oozma.springsecurity.repository;

import com.oozma.springsecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email);


    // Method to update user role by ID using custom query
    @Modifying
    @Query("UPDATE User u SET u.role = :userRole WHERE u.id = :userId")
    int updateUserRoleById(Integer userId, String userRole);

    @Query("SELECT new User(u.id, u.firstname, u.lastname, u.email) FROM User u")
    List<User> findAllUsersWithoutPasswords();
}
