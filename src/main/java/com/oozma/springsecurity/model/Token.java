package com.oozma.springsecurity.model;

import jakarta.persistence.*;
import lombok.*;

@Data
@Table(name = "tbl_token")
@Entity
@Builder
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class Token {

    @Id
    @GeneratedValue
    private Integer id;

    @Column(unique = true)
    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType=TokenType.BEARER;

    //flags
    private boolean expired;
    private boolean revoked;

    //add mapping (many tokens to a single user)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
}
