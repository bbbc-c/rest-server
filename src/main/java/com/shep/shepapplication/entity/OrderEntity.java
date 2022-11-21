package com.shep.shepapplication.entity;

import lombok.ToString;

import javax.persistence.*;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "orders")
public class OrderEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "name")
    private String name;
    @Column(name = "date_creation")
    private Date dateCreation;
    @Column(name = "date_completion")
    private Date dateCompletion;
    @Column(name = "description")
    private String description;
    @Column(name = "price")
    private Float price;
    @Column(name = "hours")
    private Float hours;
    @Column(name = "path_image")
    private String pathImage;
    @Column(name = "count_employees")
    private Integer cuntEmployees;
    @ManyToOne
    @JoinColumn(name = "address_id")
    private AddressEntity address;
    @ManyToOne
    @JoinColumn(name = "activity_id")
    private ActivityEntity activity;
    @ManyToOne
    @JoinColumn(name = "user_creation")
    private UserEntity userCreation;
    @ManyToMany
    @JoinTable(
            name = "users",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "order_id")
    )
    @ToString.Exclude
    private List<UserEntity> users;


    public OrderEntity() {
    }

    public List<UserEntity> getUsers() {
        return users;
    }

    public void setUsers(List<UserEntity> users) {
        this.users = users;
    }

    public UserEntity getUserCreation() {
        return userCreation;
    }

    public void setUserCreation(UserEntity userCreation) {
        this.userCreation = userCreation;
    }

    public ActivityEntity getActivity() {
        return activity;
    }

    public void setActivity(ActivityEntity activity) {
        this.activity = activity;
    }

    public AddressEntity getAddress() {
        return address;
    }

    public void setAddress(AddressEntity address) {
        this.address = address;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Date getDateCreation() {
        return dateCreation;
    }

    public void setDateCreation(Date dateCreation) {
        this.dateCreation = dateCreation;
    }

    public Date getDateCompletion() {
        return dateCompletion;
    }

    public void setDateCompletion(Date dateCompletion) {
        this.dateCompletion = dateCompletion;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Float getPrice() {
        return price;
    }

    public void setPrice(Float price) {
        this.price = price;
    }

    public Float getHours() {
        return hours;
    }

    public void setHours(Float hours) {
        this.hours = hours;
    }

    public String getPathImage() {
        return pathImage;
    }

    public void setPathImage(String pathImage) {
        this.pathImage = pathImage;
    }

    public Integer getCuntEmployees() {
        return cuntEmployees;
    }

    public void setCuntEmployees(Integer cuntEmployees) {
        this.cuntEmployees = cuntEmployees;
    }
}
