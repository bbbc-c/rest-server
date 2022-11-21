package com.shep.shepapplication.entity;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "activity")
public class ActivityEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "name")
    private String name;
    @OneToMany(mappedBy = "activity", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<OrderEntity> orders;

    public ActivityEntity() {
    }

    public List<OrderEntity> getOrders() {
        return orders;
    }

    public void setOrders(List<OrderEntity> orderEntity) {
        this.orders = orderEntity;
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
}
