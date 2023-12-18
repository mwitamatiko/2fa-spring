package com.oozma.springsecurity.samples;


import com.oozma.springsecurity.model.Role;
import com.oozma.springsecurity.model.User;
import com.oozma.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepository;

    @GetMapping("/access/{userId}/{userRole}")
    public String giveAccessToUser(@PathVariable("userId") Integer userId, @PathVariable("userRole") String userRole){
        Optional<User> user = userRepository.findById(userId);
        if (user.isPresent()){
            User foundUser = user.get();
            log.info("User found: {}", foundUser);
            int rowsUpdated = userRepository.updateUserRoleById(userId, userRole);
            if (rowsUpdated > 0) {
                log.info("User role updated successfully!");
            } else {
                log.info("User role update failed or user not found!");
            }
        } else {
            return "User not found with ID: " + userId;
        }
        return "something to be returned" ;
    }

    @GetMapping
    public ResponseEntity<List<User>> loadUsers(){
        return ResponseEntity.ok(userRepository.findAllUsersWithoutPasswords());
    }





//    @GetMapping
//    public String get(){
//        return "GET:: admin controller";
//    }
//    @PostMapping
//    public String post(){
//        return "POST:: admin controller";
//    }
//    @PutMapping
//    public String put(){
//        return "PUT:: admin controller";
//    }
//    @DeleteMapping
//    public String delete(){
//        return "DELETE:: admin controller";
//    }




}
