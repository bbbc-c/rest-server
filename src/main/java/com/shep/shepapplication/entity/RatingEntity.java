package com.shep.shepapplication.entity;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "rating")
public class RatingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="id")
    private Long id;
    @Column(name = "rating")
    private Float rating;
    @Column(name = "description")
    private String description;
    @Column(name = "id_user_from")
    private Long idUserFrom;
    @Column(name = "date_creation")
    private Date dateCreation;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private UserEntity user;
    public RatingEntity() {
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public Float getRating() {
        return rating;
    }

    public void setRating(Float rating) {
        this.rating = rating;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Long getIdUserFrom() {
        return idUserFrom;
    }

    public void setIdUserFrom(Long idUserFrom) {
        this.idUserFrom = idUserFrom;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

}
