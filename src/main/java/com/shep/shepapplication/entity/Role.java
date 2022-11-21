package com.shep.shepapplication.entity;

import lombok.Data;
import lombok.ToString;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "role")
@Data
@ToString
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "name")
    private String name;
    @ManyToMany(mappedBy = "roles")
    @ToString.Exclude
    private List<UserEntity> users;

}
