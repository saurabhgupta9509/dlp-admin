package com.ma.dlp.service;

import com.ma.dlp.Repository.AlertRepository;
import com.ma.dlp.dto.AlertDTO;
import com.ma.dlp.dto.AlertStatsDTO;
import com.ma.dlp.dto.AlertsByDateDTO;
import com.ma.dlp.model.Alert;
import com.ma.dlp.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class AlertService {

    @Autowired
    private AlertRepository alertRepository;

    public Alert saveAlert(Alert alert) {
        return alertRepository.save(alert);
    }

    public List<Alert> getRecentAlerts() {
        return alertRepository.findByStatusOrderByCreatedAtDesc("PENDING");
    }

//    public List<Alert> getPendingAlerts() {
//        return alertRepository.findByStatusOrderByCreatedAtDesc("PENDING");
//    }

    public List<AlertDTO> getPendingAlerts() {
        // 4. Fetch the entities from the database
        List<Alert> alerts = alertRepository.findByStatusOrderByCreatedAtDesc("PENDING");

        // 5. Convert the list of entities to a list of DTOs
        return alerts.stream()
                .map(AlertDTO::fromEntity)
                .collect(Collectors.toList());
    }

    public List<AlertDTO> getAllAlerts() {
        List<Alert> alerts = alertRepository.findAllByOrderByCreatedAtDesc();
        return alerts.stream()
                .map(AlertDTO::fromEntity)
                .collect(Collectors.toList());
    }

    public List<Alert> getAgentAlerts(Long agentId) {
        return alertRepository.findByAgentIdOrderByCreatedAtDesc(agentId);
    }

    // CHANGE THE RETURN TYPE from Alert to AlertDTO
    public AlertDTO handleDecision(Long alertId, String decision) {
        Alert alert = alertRepository.findById(alertId)
                .orElseThrow(() -> new RuntimeException("Alert not found"));

        alert.setStatus(decision.toUpperCase()); // Set the new status
        alert.setResolvedAt(new Date()); // Mark as resolved

        Alert updatedAlert = alertRepository.save(alert);

        // Convert to DTO before returning
        return AlertDTO.fromEntity(updatedAlert);
    }


    public Alert createAlert(User agent, String alertType, String description, String deviceInfo, String fileDetails) {
        Alert alert = new Alert();
        alert.setAgent(agent);
        alert.setAlertType(alertType);
        alert.setDescription(description);
        alert.setDeviceInfo(deviceInfo);
        alert.setFileDetails(fileDetails);
        alert.setSeverity("MEDIUM");
        alert.setStatus("PENDING");
        alert.setActionTaken("DETECTED");

        return alertRepository.save(alert);
    }

    public List<Alert> getAlertsBySeverity(String severity) {
        return alertRepository.findBySeverityAndStatus(severity, "PENDING");
    }

    public long getPendingAlertCount() {
        return alertRepository.findByStatusOrderByCreatedAtDesc("PENDING").size();
    }

    // THIS METHOD for the Pie Chart
    public List<AlertStatsDTO> getAlertSummaryBySeverity() {
        return alertRepository.countBySeverity();
    }

    public List<AlertsByDateDTO> getAlertSummaryByDate() {
        List<Map<String, Object>> results = alertRepository.countByDateLast7Days();

        return results.stream().map(row -> {
            // Safely convert the date object
            Date date = null;
            Object dateObj = row.get("date");
            if (dateObj instanceof java.sql.Date) {
                date = new java.util.Date(((java.sql.Date) dateObj).getTime());
            } else if (dateObj instanceof java.sql.Timestamp) {
                date = new java.util.Date(((java.sql.Timestamp) dateObj).getTime());
            } else if (dateObj instanceof java.util.Date) {
                date = (java.util.Date) dateObj;
            }

            // Safely convert the count
            long count = 0;
            Object countObj = row.get("count");
            if (countObj instanceof BigInteger) {
                count = ((BigInteger) countObj).longValue();
            } else if (countObj instanceof Long) {
                count = (Long) countObj;
            } else if (countObj instanceof Number) {
                count = ((Number) countObj).longValue();
            }

            return new AlertsByDateDTO(date, count);
        }).collect(Collectors.toList());
    }
}