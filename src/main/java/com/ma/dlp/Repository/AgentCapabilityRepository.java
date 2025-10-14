package com.ma.dlp.Repository;

import com.ma.dlp.model.AgentCapability;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AgentCapabilityRepository extends JpaRepository<AgentCapability, Long> {
    List<AgentCapability> findByAgentId(Long agentId);

    List<AgentCapability> findByAgentIdAndIsActiveTrue(Long agentId);

    Optional<AgentCapability> findByAgentIdAndCapabilityCode(Long agentId, String capabilityCode);

    boolean existsByAgentIdAndCapabilityCode(Long agentId, String capabilityCode);

    @Query("SELECT ac FROM AgentCapability ac WHERE ac.agent.id = :agentId AND ac.isActive = true")
    List<AgentCapability> findActiveCapabilitiesByAgentId(@Param("agentId") Long agentId);

    @Modifying
    @Query("DELETE FROM AgentCapability ac WHERE ac.agent.id = :agentId")
    void deleteByAgentId(@Param("agentId") Long agentId);

    @Query("SELECT DISTINCT ac.category FROM AgentCapability ac WHERE ac.agent.id = :agentId")
    List<String> findDistinctCategoriesByAgentId(@Param("agentId") Long agentId);


    List<AgentCapability> findByCapabilityCode(String capabilityCode);

}
