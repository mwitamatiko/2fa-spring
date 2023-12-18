package com.oozma.springsecurity.repository;

import com.oozma.springsecurity.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Integer> {

    //fetch all tokens for specific user

    @Query("""
      select t from Token t inner join User u on t.user.id = u.id
      where u.id= :userId and (t.expired=false or t.revoked=false)
""")
    List<Token> findAllValidTokensByUser(Integer userId);

    //find token by token
    Optional<Token> findByToken(String token);
}
