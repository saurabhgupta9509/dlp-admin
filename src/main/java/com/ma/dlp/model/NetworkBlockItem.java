package com.ma.dlp.model;

import lombok.Data;
import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "network_blocklist")
@Data
public class NetworkBlockItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private BlockType type; // e.g., DOMAIN or IP_ADDRESS

    @Column(nullable = false, unique = true)
    private String value; // e.g., "dropbox.com" or "8.8.8.8"

    private String description;

    @Temporal(TemporalType.TIMESTAMP)
    private Date createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = new Date();
    }

    public enum BlockType {
        DOMAIN,
        IP_ADDRESS
    }
}