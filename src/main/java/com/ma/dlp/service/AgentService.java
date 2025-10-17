package com.ma.dlp.service;//package com.ma.dlp.service;

import com.ma.dlp.Repository.AgentCapabilityRepository;
import com.ma.dlp.Repository.PolicyRepository;
import com.ma.dlp.Repository.UserRepository;
import com.ma.dlp.dto.AgentPolicyStatusDTO;
import com.ma.dlp.dto.PolicyCapabilityDTO;
import com.ma.dlp.model.AgentCapability;
import com.ma.dlp.model.Alert;
import com.ma.dlp.model.Policy;
import com.ma.dlp.model.User;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.ma.dlp.dto.PolicyCapabilityDTO; // Make sure this is imported
import java.util.stream.Collectors;


import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AgentService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PolicyRepository policyRepository;

    @Autowired
    private AgentCapabilityRepository agentCapabilityRepository;

    private static final Logger log = LoggerFactory.getLogger(AgentService.class);

    private final ConcurrentHashMap<String, Long> agentTokens = new ConcurrentHashMap<>();
    private final Map<String, PendingAgent> pendingAgents = new ConcurrentHashMap<>();

    // In service/AgentService.java

    @Transactional
    public void saveAgentCapabilities(Long agentId, List<PolicyCapabilityDTO> capabilities) {
        User agent = userRepository.findById(agentId)
                .orElseThrow(() -> new RuntimeException("Agent not found: " + agentId));

        // Step 1: Sync the master 'policies' table (This is correct)
        syncPoliciesWithCapabilities(capabilities);

        // --- NEW LOGIC ---
        // Step 2: Get the list of capabilities already saved for this agent
        List<AgentCapability> existingCapabilities = agentCapabilityRepository.findByAgentId(agentId);
        Set<String> existingCodes = existingCapabilities.stream()
                .map(AgentCapability::getCapabilityCode)
                .collect(Collectors.toSet());

        // Step 3: Only add new capabilities that are not already in the database
        for (PolicyCapabilityDTO capDto : capabilities) {
            if (!existingCodes.contains(capDto.getCode())) {
                // This capability is new for this agent, so create it
                AgentCapability agentCap = new AgentCapability();
                agentCap.setAgent(agent);
                agentCap.setCapabilityCode(capDto.getCode());
                agentCap.setName(capDto.getName());
                agentCap.setDescription(capDto.getDescription());
                agentCap.setCategory(capDto.getCategory());
                agentCap.setAction(capDto.getAction());
                agentCap.setTarget(capDto.getTarget());
                agentCap.setSeverity(capDto.getSeverity());
                agentCap.setIsActive(false); // Always start new capabilities as INACTIVE

                agentCapabilityRepository.save(agentCap);
                log.info("✅ Discovered and saved new capability '{}' for agent {}", capDto.getCode(), agent.getUsername());
            }
        }

        log.info("✅ Agent capability sync complete for agent: {}", agent.getUsername());
    }



    private void syncPoliciesWithCapabilities(List<PolicyCapabilityDTO> capabilities) {
        for (PolicyCapabilityDTO cap : capabilities) {
            // Check if a policy with this code already exists
            if (policyRepository.findByPolicyCode(cap.getCode()).isEmpty()) {
                // If it doesn't exist, create it
                Policy newPolicy = new Policy();
                newPolicy.setPolicyCode(cap.getCode());
                newPolicy.setName(cap.getName());
                newPolicy.setDescription(cap.getDescription());
                newPolicy.setCategory(cap.getCategory());

                // --- THESE ARE THE MISSING LINES ---
                newPolicy.setAction(cap.getAction());
                newPolicy.setTarget(cap.getTarget());
                newPolicy.setSeverity(cap.getSeverity());
                newPolicy.setPolicyType(cap.getAction() + "_" + cap.getCategory());
                newPolicy.setIsActive(false); // Master policy is a template, not active
                // ------------------------------------

                policyRepository.save(newPolicy);
                log.info("✅ Created new master policy from agent capability: {}", cap.getCode());
            }
        }
    }
    /**
     * Activate a capability for an agent
     */
    public void activateCapability(Long agentId, String capabilityCode , String policyData) {
        AgentCapability capability = agentCapabilityRepository
                .findByAgentIdAndCapabilityCode(agentId, capabilityCode)
                .orElseThrow(() -> new RuntimeException(
                        String.format("Capability %s not found for agent %d", capabilityCode, agentId)));

        // --- THIS IS THE NEW CHECK ---
        if (Boolean.TRUE.equals(capability.getIsActive())) {
            // Get the agent's name to make the error message more user-friendly
            String agentName = capability.getAgent() != null ? capability.getAgent().getHostname() : "ID " + agentId;
            throw new IllegalStateException("Policy is already active for agent: " + agentName);
        }
        // --- END OF NEW CHECK ---

        capability.setIsActive(true);
        capability.setAssignedAt(new Date());
        capability.setPolicyData(policyData);
        agentCapabilityRepository.save(capability);

        log.info("✅ Activated capability '{}' for agent: {}", capabilityCode, agentId);
    }

    /**
     * Deactivate a capability for an agent
     */
    public void deactivateCapability(Long agentId, String capabilityCode) {
        AgentCapability capability = agentCapabilityRepository
                .findByAgentIdAndCapabilityCode(agentId, capabilityCode)
                .orElseThrow(() -> new RuntimeException(
                        String.format("Capability %s not found for agent %d", capabilityCode, agentId)));

        capability.setIsActive(false);
        agentCapabilityRepository.save(capability);

        log.info("✅ Deactivated capability '{}' for agent: {}", capabilityCode, agentId);
    }

    /**
     * Get active capabilities for an agent
     */
    public List<AgentCapability> getActiveCapabilities(Long agentId) {
        return agentCapabilityRepository.findActiveCapabilitiesByAgentId(agentId);
    }

    /**
     * Get all capabilities for an agent
     */
    public List<AgentCapability> getAllCapabilities(Long agentId) {
        return agentCapabilityRepository.findByAgentId(agentId);
    }

    /**
    * Get all agents policy statuses
     */

    public List<AgentPolicyStatusDTO> getAgentPolicyStatuses(String capabilityCode) {
        // 1. Find all capability records for this policy
        List<AgentCapability> capabilities = agentCapabilityRepository.findByCapabilityCode(capabilityCode);

        // 2. Convert them into the new DTO
        return capabilities.stream().map(cap -> {
            AgentPolicyStatusDTO dto = new AgentPolicyStatusDTO();
            dto.setAgentId(cap.getAgent().getId());
            dto.setHostname(cap.getAgent().getHostname());
            dto.setAgentStatus(cap.getAgent().getStatus().toString());
            dto.setIsPolicyActive(cap.getIsActive());
            return dto;
        }).collect(Collectors.toList());
    }



    public List<User> getAgentsWithCapability(String capabilityCode) {
        List<AgentCapability> capabilities = agentCapabilityRepository.findByCapabilityCode(capabilityCode);

        // Convert the list of AgentCapability objects to a distinct list of User objects
        return capabilities.stream()
                .map(AgentCapability::getAgent)
                .distinct()
                .collect(Collectors.toList());
    }

    /**
     * Get capabilities grouped by category for dashboard
     */
    public Map<String, List<PolicyCapabilityDTO>> getCapabilitiesByCategory(Long agentId) {
        List<AgentCapability> capabilities = agentCapabilityRepository.findByAgentId(agentId);
        Map<String, List<PolicyCapabilityDTO>> result = new HashMap<>();

        for (AgentCapability capability : capabilities) {
            PolicyCapabilityDTO capabilityDto = convertToDto(capability);
            result.computeIfAbsent(capability.getCategory(), k -> new ArrayList<>())
                    .add(capabilityDto);
        }

        return result;
    }


    /**
     * Updates the data for an existing policy assignment
     * without changing its active status.
     */
    @Transactional
    public void updatePolicyData(Long agentId, String capabilityCode, String policyData) {
        AgentCapability capability = agentCapabilityRepository
                .findByAgentIdAndCapabilityCode(agentId, capabilityCode)
                .orElseThrow(() -> new RuntimeException(
                        String.format("Capability %s not found for agent %d", capabilityCode, agentId)));

        // Set the new data
        capability.setPolicyData(policyData);
        agentCapabilityRepository.save(capability);

        log.info("✅ Updated policy data for '{}' on agent: {}", capabilityCode, agentId);
    }


    // ADD THIS NEW HELPER METHOD
    private PolicyCapabilityDTO convertToDto(AgentCapability entity) {
        PolicyCapabilityDTO dto = new PolicyCapabilityDTO();
        dto.setCode(entity.getCapabilityCode());
        dto.setName(entity.getName());
        dto.setDescription(entity.getDescription());
        dto.setCategory(entity.getCategory());
        dto.setAction(entity.getAction());
        dto.setTarget(entity.getTarget());
        dto.setSeverity(entity.getSeverity());
        dto.setIsActive(entity.getIsActive()); // Pass the status to the DTO

        dto.setPolicyData(entity.getPolicyData() != null ? entity.getPolicyData() : "");

        return dto;
    }


    public AgentAuthResponse authenticateAgent(String hostname, String macAddress) {
        List<User> existingAgents = userRepository.findAllByMacAddress(macAddress);
        User agent;

        if (!existingAgents.isEmpty()) {
            agent = existingAgents.stream()
                    .max(Comparator.comparing(User::getLastLogin,
                            Comparator.nullsFirst(Comparator.naturalOrder())))
                    .orElse(existingAgents.get(0));
            log.info("🔄 Existing agent found: {}", agent.getUsername());

            // ✅ Check if existing agent has null plainPassword and fix it
            if (agent.getPlainPassword() == null) {
                String newPassword = generateSecurePassword();
                agent.setPlainPassword(newPassword);
                agent.setPassword(passwordEncoder.encode(newPassword));
                userRepository.save(agent);
                log.info("🔑 Fixed null password for existing agent: {}", agent.getUsername());
            }
        } else {
            // ✅ Use the updated createAgent method with 4 parameters
            agent = createAgent(hostname, macAddress, null, null); // null for custom password = auto-generate
            log.info("✅ New agent created: {}", agent.getUsername());
        }

        agent.setLastLogin(new Date());
        userRepository.save(agent);

        return new AgentAuthResponse(
                agent.getId(),
                agent.getUsername(),
                agent.getPlainPassword(),
                "ACTIVE",
                generateToken()
        );
    }

    // In AgentService.java - update createAgentDirectly method
    public AgentAuthResponse createAgentDirectly(String hostname, String macAddress, String username, String customPassword) {
        // ✅ Accept custom password parameter
        try {
            User agent = createAgent(hostname, macAddress, username, customPassword);
            String token = generateToken();
            agentTokens.put(token, agent.getId());

            log.info("✅ Admin directly created agent: {} (MAC: {})", hostname, macAddress);
            log.info("🔑 Agent credentials - Username: {}, Password: {}",
                    agent.getUsername(), agent.getPlainPassword());

            return new AgentAuthResponse(
                    agent.getId(),
                    agent.getUsername(),
                    agent.getPlainPassword(),
                    "ACTIVE",
                    token
            );
        } catch (Exception e) {
            log.error("❌ Failed to create agent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create agent: " + e.getMessage());
        }
    }

    public String registerAgent(String hostname, String macAddress) {
        List<User> existingAgents = userRepository.findAllByMacAddress(macAddress);
        if (!existingAgents.isEmpty()) {
            throw new RuntimeException("Agent already registered with this MAC address");
        }

        String pendingId = UUID.randomUUID().toString();
        PendingAgent pendingAgent = new PendingAgent(pendingId, hostname, macAddress);
        pendingAgents.put(pendingId, pendingAgent);

        createPendingAgentAlert(hostname, macAddress, pendingId);

        return pendingId;
    }

    public AgentAuthResponse checkAgentApproval(String pendingId) {
        PendingAgent pendingAgent = pendingAgents.get(pendingId);
        if (pendingAgent == null) {
            throw new RuntimeException("Pending agent not found");
        }

        // ✅ Use the updated createAgent method
        User agent = createAgent(pendingAgent.getHostname(), pendingAgent.getMacAddress(), null, null);
        pendingAgents.remove(pendingId);

        return new AgentAuthResponse(
                agent.getId(),
                agent.getUsername(),
                agent.getPlainPassword(),
                "ACTIVE",
                generateToken()
        );
    }

    public AgentAuthResponse loginWithCredentials(String username, String password) {
        Optional<User> agentOpt = userRepository.findByUsername(username);
        if (agentOpt.isEmpty()) {
            throw new RuntimeException("Agent not found");
        }

        User agent = agentOpt.get();

        if (!passwordEncoder.matches(password, agent.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (agent.getStatus() != User.UserStatus.ACTIVE) {
            throw new RuntimeException("Agent account is not active");
        }

        // ✅ Check if plainPassword is null and fix it
        if (agent.getPlainPassword() == null) {
            // For credential login, we don't know the plain password, so generate a new one
            String newPassword = generateSecurePassword();
            agent.setPlainPassword(newPassword);
            // Don't change the encoded password since the current one works
            userRepository.save(agent);
            log.info("🔑 Fixed null plainPassword for agent: {}", agent.getUsername());
        }

        String token = generateToken();
        agentTokens.put(token, agent.getId());

        agent.setLastLogin(new Date());
        userRepository.save(agent);

        log.info("✅ Agent logged in with credentials: {}", username);

        return new AgentAuthResponse(
                agent.getId(),
                agent.getUsername(),
                agent.getPlainPassword(), // This should not be null now
                agent.getStatus().toString(),
                token
        );
    }

    private void createPendingAgentAlert(String hostname, String macAddress, String pendingId) {
        try {
            Alert alert = new Alert();
            alert.setAlertType("AGENT_REGISTRATION_REQUEST");
            alert.setDescription(String.format(
                    "New agent registration request: %s (MAC: %s). Pending ID: %s",
                    hostname, macAddress, pendingId
            ));
            alert.setSeverity("MEDIUM");
            alert.setStatus("PENDING");
            alert.setActionTaken("PENDING_APPROVAL");
            alert.setDeviceInfo(String.format("Hostname: %s, MAC: %s", hostname, macAddress));

            log.info("📝 Created pending agent alert: {} - {}", hostname, macAddress);
        } catch (Exception e) {
            log.error("Failed to create pending agent alert", e);
        }
    }

    // In AgentService.java - add detailed logging to createAgent method
    private User createAgent(String hostname, String macAddress, String customUsername, String customPassword) {
        log.info("🔍 CREATE_AGENT DEBUG - Start:");
        log.info("  Hostname: {}", hostname);
        log.info("  MAC: {}", macAddress);
        log.info("  Custom Username: {}", customUsername);
        log.info("  Custom Password: {}", customPassword);

        List<User> existingAgents = userRepository.findAllByMacAddress(macAddress);
        log.info("  Existing agents found: {}", existingAgents.size());

        if (!existingAgents.isEmpty()) {
            User existingAgent = existingAgents.get(0);
            log.info("  🔄 Returning existing agent: {}", existingAgent.getUsername());
            log.info("  Existing agent plainPassword: {}", existingAgent.getPlainPassword());
            return existingAgent;
        }

        String username = customUsername != null ? customUsername :
                "agent_" + hostname.toLowerCase().replace(" ", "_");
        log.info("  Final username: {}", username);

        String plainPassword = (customPassword != null && !customPassword.trim().isEmpty()) ?
                customPassword : generateSecurePassword();
        log.info("  Final plainPassword: {}", plainPassword);

        User agent = new User();
        agent.setUsername(username);
        agent.setPassword(passwordEncoder.encode(plainPassword));
        agent.setRole(User.UserRole.AGENT);
        agent.setStatus(User.UserStatus.ACTIVE);
        agent.setHostname(hostname);
        agent.setMacAddress(macAddress);
        agent.setLastHeartbeat(new Date());
        agent.setPlainPassword(plainPassword);

        log.info("  Before save - agent.plainPassword: {}", agent.getPlainPassword());

        User savedAgent = userRepository.save(agent);

        log.info("  After save - savedAgent.plainPassword: {}", savedAgent.getPlainPassword());
        log.info("  ✅ Agent created successfully");

        return savedAgent;
    }

    private String generateSecurePassword() {
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
        StringBuilder password = new StringBuilder();
        Random random = new Random();

        for (int i = 0; i < 12; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }

    public boolean validateToken(String token, Long agentId) {
        return token != null && token.startsWith("Bearer ");
    }

    public void updateHeartbeat(Long agentId) {
        userService.updateHeartbeat(agentId);
    }

    public String generateToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public void rejectAgent(String pendingId) {
        pendingAgents.remove(pendingId);
    }

    public List<PendingAgent> getPendingAgents() {
        return new ArrayList<>(pendingAgents.values());
    }

    @Data
    public static class AgentAuthResponse {
        private Long userId;
        private Long agentId;
        private String username;
        private String password;
        private String status;
        private String token;

        public AgentAuthResponse(Long agentId, String username, String password, String status, String token) {
            this.agentId = agentId;
            this.userId = agentId;
            this.username = username;
            this.password = password;
            this.status = status;
            this.token = token;
        }
        public Long getUserId() { return userId; }
        public void setUserId(Long userId) { this.userId = userId; }

        public void setAgentId(Long agentId) {
            this.agentId = agentId;
            this.userId = agentId;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
        public Long getAgentId() { return agentId; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getStatus() { return status; }
    }

    @Data
    public static class PendingAgent {
        private String pendingId;
        private String hostname;
        private String macAddress;
        private Date requestTime;

        public PendingAgent(String pendingId, String hostname, String macAddress) {
            this.pendingId = pendingId;
            this.hostname = hostname;
            this.macAddress = macAddress;
            this.requestTime = new Date();
        }

        public String getHostname() { return hostname; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        public String getMacAddress() { return macAddress; }
        public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
        public String getPendingId() { return pendingId; }
        public void setPendingId(String pendingId) { this.pendingId = pendingId; }
        public Date getRequestTime() { return requestTime; }
        public void setRequestTime(Date requestTime) { this.requestTime = requestTime; }
    }
}

