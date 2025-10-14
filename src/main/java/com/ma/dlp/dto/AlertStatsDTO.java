package com.ma.dlp.dto;

// We are not using Lombok annotations
public class AlertStatsDTO {

    private String severity;
    private long count;

    /**
     * An empty constructor is required by JPA/Hibernate.
     */
    public AlertStatsDTO() {
    }

    /**
     * This is the constructor that your @Query is looking for.
     * It takes a String (severity) and a long (count).
     */
    public AlertStatsDTO(String severity, long count) {
        this.severity = severity;
        this.count = count;
    }

    // --- Manual Getters ---

    public String getSeverity() {
        return severity;
    }

    public long getCount() {
        return count;
    }

    // --- Manual Setters ---

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public void setCount(long count) {
        this.count = count;
    }
}