package com.ma.dlp.dto;

import java.util.Date;

// We have removed @Data, @NoArgsConstructor, and @AllArgsConstructor
public class AlertsByDateDTO {

    private Date date;
    private long count;

    // 1. The empty constructor (required by some frameworks)
    public AlertsByDateDTO() {
    }

    // 2. The constructor your service needs (Date first, then long)
    public AlertsByDateDTO(Date date, long count) {
        this.date = date;
        this.count = count;
    }

    // 3. Manual Getters
    public Date getDate() {
        return date;
    }

    public long getCount() {
        return count;
    }

    // 4. Manual Setters
    public void setDate(Date date) {
        this.date = date;
    }

    public void setCount(long count) {
        this.count = count;
    }
}