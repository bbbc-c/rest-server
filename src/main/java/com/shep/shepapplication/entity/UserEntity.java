package com.shep.shepapplication.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.apache.catalina.User;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "user")
@Data
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "name")
    private String name;
    @Column(name = "surname")
    private String surname;
    @Column(name = "patronymic")
    private String patronymic;
    @Column(name = "login")
    private String login;
    @Column(name = "password")
    private String password;
    @Column(name = "phone_number")
    private String phoneNumber;
    @Column(name = "email")
    private String email;
    @Column(name = "about_me")
    private String aboutMe;
    @Column(name = "path_image")
    private String pathImage;
    @Column(name = "date_reg")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private Date dateRegistration;
    @Column(name = "hours_work")
    private Float hoursWork;
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private Status status;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "userCreation",fetch = FetchType.LAZY)
    private List<OrderEntity> ordersCreation;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "user")
    private List<RatingEntity> ratings;
    @ManyToMany(mappedBy = "users")
    private List<OrderEntity> orders;
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "users_roles",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id", referencedColumnName = "id")}
    )
    private List<Role> roles;

    public UserEntity() {
    }

}
