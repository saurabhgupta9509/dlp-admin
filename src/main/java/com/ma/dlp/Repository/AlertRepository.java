// AlertRepository.java
package com.ma.dlp.Repository;


import com.ma.dlp.dto.AlertStatsDTO;
import com.ma.dlp.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Date;
import java.util.Map;

@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {
    List<Alert> findByStatusOrderByCreatedAtDesc(String status);
    List<Alert> findAllByOrderByCreatedAtDesc();


    List<Alert> findByAgentIdOrderByCreatedAtDesc(Long agentId);
    List<Alert> findByCreatedAtAfter(Date date);
    List<Alert> findBySeverityAndStatus(String severity, String status);
    List<Alert> findByStatus(String status);

    // ADD THIS QUERY for the Pie Chart
    @Query("SELECT new com.ma.dlp.dto.AlertStatsDTO(a.severity, COUNT(a)) FROM Alert a GROUP BY a.severity")
    List<AlertStatsDTO> countBySeverity();

    // ADD THIS QUERY for the Bar Chart (MySQL compatible)
    @Query(value = "SELECT CAST(a.created_at AS DATE) as date, COUNT(a.id) as count " +
            "FROM alerts a " +
            "WHERE a.created_at >= CURDATE() - INTERVAL 7 DAY " +
            "GROUP BY CAST(a.created_at AS DATE) " +
            "ORDER BY date ASC", nativeQuery = true)
    List<Map<String, Object>> countByDateLast7Days();
}