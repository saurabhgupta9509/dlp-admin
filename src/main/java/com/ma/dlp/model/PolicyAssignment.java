//package com.ma.dlp.model;
//
//import lombok.Data;
//import jakarta.persistence.*;
//import java.util.Date;
//
//@Entity
//@Table(name = "policy_assignments")
//@Data
//public class PolicyAssignment {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "user_id", nullable = false)
//    private User user;
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "policy_id", nullable = false)
//    private Policy policy;
//
//    @Column(nullable = false)
//    private String status; // ACTIVE, INACTIVE
//
//    private Date assignedAt;
//    private Date effectiveFrom;
//    private Date effectiveUntil;
//
//    @PrePersist
//    protected void onCreate() {
//        assignedAt = new Date();
//        if (status == null) {
//            status = "ACTIVE";
//        }
//        if (effectiveFrom == null) {
//            effectiveFrom = new Date();
//        }
//    }
//
//    public Date getAssignedAt() {
//        return assignedAt;
//    }
//
//    public void setAssignedAt(Date assignedAt) {
//        this.assignedAt = assignedAt;
//    }
//
//    public Date getEffectiveFrom() {
//        return effectiveFrom;
//    }
//
//    public void setEffectiveFrom(Date effectiveFrom) {
//        this.effectiveFrom = effectiveFrom;
//    }
//
//    public Date getEffectiveUntil() {
//        return effectiveUntil;
//    }
//
//    public void setEffectiveUntil(Date effectiveUntil) {
//        this.effectiveUntil = effectiveUntil;
//    }
//
//    public Long getId() {
//        return id;
//    }
//
//    public void setId(Long id) {
//        this.id = id;
//    }
//
//    public Policy getPolicy() {
//        return policy;
//    }
//
//    public void setPolicy(Policy policy) {
//        this.policy = policy;
//    }
//
//    public String getStatus() {
//        return status;
//    }
//
//    public void setStatus(String status) {
//        this.status = status;
//    }
//
//    public User getUser() {
//        return user;
//    }
//
//    public void setUser(User user) {
//        this.user = user;
//    }
//}