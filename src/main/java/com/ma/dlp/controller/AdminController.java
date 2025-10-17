package com.ma.dlp.controller;

import com.ma.dlp.Repository.PolicyRepository;
import com.ma.dlp.dto.*;
import com.ma.dlp.model.*;
import com.ma.dlp.service.AgentService;
import com.ma.dlp.service.AlertService;
import com.ma.dlp.service.PolicyService;
import com.ma.dlp.service.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private AlertService alertService;

    @Autowired
    private AgentService agentService;

    @Autowired
    private PolicyRepository policyRepository;

    @Autowired
    private PolicyService policyService;

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    // In AdminController.java - update the createAgent endpoint
    @PostMapping("/agents/create")
    public ResponseEntity<ApiResponse<AgentService.AgentAuthResponse>> createAgent(
            @RequestBody CreateAgentRequest request,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            // ✅ Pass the custom password to the service method
            AgentService.AgentAuthResponse response = agentService.createAgentDirectly(
                    request.getHostname(),
                    request.getMacAddress(),
                    request.getUsername(),
                    request.getPassword()  // ✅ Pass the custom password
            );
            return ResponseEntity.ok(new ApiResponse<>(true, "Agent created successfully", response));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to create agent: " + e.getMessage()));
        }
    }

    // In AdminController.java - add debug endpoint
    @GetMapping("/debug/agent-by-mac/{macAddress}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> debugAgentByMac(
            @PathVariable String macAddress,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            List<User> agents = userService.findByMacAddress(macAddress);
            Map<String, Object> debugInfo = new HashMap<>();
            debugInfo.put("macAddress", macAddress);
            debugInfo.put("agentsFound", agents.size());

            List<Map<String, Object>> agentDetails = new ArrayList<>();
            for (User agent : agents) {
                Map<String, Object> agentInfo = new HashMap<>();
                agentInfo.put("id", agent.getId());
                agentInfo.put("username", agent.getUsername());
                agentInfo.put("hostname", agent.getHostname());
                agentInfo.put("plainPassword", agent.getPlainPassword());
                agentInfo.put("hasEncodedPassword", agent.getPassword() != null);
                agentDetails.add(agentInfo);
            }
            debugInfo.put("agents", agentDetails);

            return ResponseEntity.ok(new ApiResponse<>(true, "Agent debug by MAC", debugInfo));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Debug failed: " + e.getMessage()));
        }
    }

    // In AdminController.java - Fix getAllAgents method
    @GetMapping("/agents")
    public ResponseEntity<ApiResponse<List<AgentDTO>>> getAllAgents(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            List<User> agents = userService.getAllAgents();
            List<AgentDTO> agentDTOs = agents.stream()
                    .map(agent -> {
                        AgentDTO dto = AgentDTO.fromUser(agent);
                        try {
                            List<AgentCapability> capabilities = agentService.getAllCapabilities(agent.getId());
                            dto.setCapabilityCount(capabilities != null ? capabilities.size() : 0);
                            dto.setActivePolicyCount(capabilities != null ?
                                    (int) capabilities.stream()
                                            .filter(cap -> cap != null && cap.getIsActive() != null && cap.getIsActive())
                                            .count() : 0);
                        } catch (Exception e) {
                            log.warn("Failed to get capabilities for agent {}: {}", agent.getId(), e.getMessage());
                            dto.setCapabilityCount(0);
                            dto.setActivePolicyCount(0);
                        }
                        return dto;
                    })
                    .toList();

            log.info("📊 Returning {} agents to admin", agentDTOs.size());
            return ResponseEntity.ok(new ApiResponse<>(true, "Agents retrieved successfully", agentDTOs));
        } catch (Exception e) {
            log.error("❌ Error getting agents: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to get agents: " + e.getMessage()));
        }
    }

    @PutMapping("/agents/{id}/status")
    public ResponseEntity<ApiResponse<User>> updateAgentStatus(
            @PathVariable Long id,
            @RequestParam String status,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            User.UserStatus userStatus = User.UserStatus.valueOf(status.toUpperCase());
            User updatedUser = userService.updateUserStatus(id, userStatus);
            return ResponseEntity.ok(new ApiResponse<>(true, "User status updated", updatedUser));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to update status: " + e.getMessage()));
        }
    }


    @GetMapping("/pending-agents")
    public ResponseEntity<ApiResponse<List<AgentService.PendingAgent>>> getPendingAgents(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        List<AgentService.PendingAgent> pendingAgents = agentService.getPendingAgents();
        return ResponseEntity.ok(new ApiResponse<>(true, "Pending agents retrieved", pendingAgents));
    }

    @PostMapping("/approve-agent/{pendingId}")
    public ResponseEntity<ApiResponse<AgentService.AgentAuthResponse>> approveAgent(
            @PathVariable String pendingId,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            AgentService.AgentAuthResponse response = agentService.checkAgentApproval(pendingId);
            return ResponseEntity.ok(new ApiResponse<>(true, "Agent approved successfully", response));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Approval failed: " + e.getMessage()));
        }
    }

    @PostMapping("/reject-agent/{pendingId}")
    public ResponseEntity<ApiResponse<String>> rejectAgent(
            @PathVariable String pendingId,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            agentService.rejectAgent(pendingId);
            return ResponseEntity.ok(new ApiResponse<>(true, "Agent rejected successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Rejection failed: " + e.getMessage()));
        }
    }
    @PostMapping("/agents/{id}/reset-password")
    public ResponseEntity<ApiResponse<String>> resetAgentPassword(
            @PathVariable Long id,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        ApiResponse<String> response = userService.resetAgentPassword(id);
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @DeleteMapping("/agents/{id}")
    public ResponseEntity<ApiResponse<String>> deleteAgent(@PathVariable Long id, HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            userService.deleteUser(id);
            return ResponseEntity.ok(new ApiResponse<>(true, "Agent deleted successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to delete agent: " + e.getMessage()));
        }
    }

//    @GetMapping("/policies")
//    public ResponseEntity<ApiResponse<List<PolicyDTO>>> getAllPolicies(HttpSession session) {
//        if (!isAdminAuthenticated(session)) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(new ApiResponse<>(false, "Admin access required"));
//        }
//
//        List<Policy> policies = policyService.getAllPolicies();
//        List<PolicyDTO> policyDTOs = policies.stream()
//                .map(PolicyDTO::fromPolicy)
//                .toList();
//        return ResponseEntity.ok(new ApiResponse<>(true, "Policies retrieved successfully", policyDTOs));
//    }

//    @GetMapping("/protection-policies")
//    public ResponseEntity<ApiResponse<Map<String, List<Policy>>>> getProtectionPolicies(HttpSession session) {
//        if (!isAdminAuthenticated(session)) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(new ApiResponse<>(false, "Admin access required"));
//        }
//
//        Map<String, List<Policy>> policies = new HashMap<>();
//        policies.put("USB", policyService.getPrebuiltPoliciesByCategory("USB"));
//        policies.put("NETWORK", policyService.getPrebuiltPoliciesByCategory("NETWORK"));
//        policies.put("FILE", policyService.getPrebuiltPoliciesByCategory("FILE"));
//
//        return ResponseEntity.ok(new ApiResponse<>(true, "Protection policies retrieved", policies));
//    }


    //its new
//    @GetMapping("/protection-policies")
//    public ResponseEntity<ApiResponse<Map<String, List<Policy>>>> getProtectionPolicies(HttpSession session) {
//        if (!isAdminAuthenticated(session)) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(new ApiResponse<>(false, "Admin access required"));
//        }
//
//        try {
//            Map<String, List<Policy>> policiesByCategory = new HashMap<>();
//            List<User> agents = userService.getAllAgents();
//
//            for (User agent : agents) {
//                Map<String, List<AgentCapability>> agentCapabilities =
//                        agentService.getCapabilitiesByCategory(agent.getId());
//
//                for (Map.Entry<String, List<AgentCapability>> entry : agentCapabilities.entrySet()) {
//                    String category = entry.getKey();
//                    List<Policy> categoryPolicies = entry.getValue().stream()
//                            .map(capability -> convertToPolicy(capability, agent))
//                            .toList();
//
//                    policiesByCategory
//                            .computeIfAbsent(category, k -> new ArrayList<>())
//                            .addAll(categoryPolicies);
//                }
//            }
//
//            log.info("🛡️ Returning protection policies: {} categories", policiesByCategory.size());
//            return ResponseEntity.ok(new ApiResponse<>(true, "Protection policies retrieved", policiesByCategory));
//        } catch (Exception e) {
//            log.error("❌ Error getting protection policies: {}", e.getMessage());
//            return ResponseEntity.badRequest()
//                    .body(new ApiResponse<>(false, "Failed to get protection policies: " + e.getMessage()));
//        }
//    }

    // Replace your getProtectionPolicies method with this one
    @GetMapping("/protection-policies")
    public ResponseEntity<ApiResponse<Map<String, List<Policy>>>> getProtectionPolicies(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            // This is now fully dynamic. It first finds what categories exist.
            List<String> distinctCategories = policyRepository.findDistinctCategories();

            Map<String, List<Policy>> policiesByCategory = new HashMap<>();

            // Then, for each category it found, it fetches the corresponding policies.
            for (String category : distinctCategories) {
                policiesByCategory.put(category, policyService.getPoliciesByCategory(category));
            }

            log.info("🛡️ Returning protection policies for {} dynamically found categories", policiesByCategory.size());
            return ResponseEntity.ok(new ApiResponse<>(true, "Protection policies retrieved", policiesByCategory));

        } catch (Exception e) {
            log.error("❌ Error getting protection policies: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to get protection policies: " + e.getMessage()));
        }
    }

    @PostMapping("/assign-protection")
    public ResponseEntity<ApiResponse<String>> assignProtectionPolicy(
            @RequestBody ProtectionAssignmentRequest request,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            int successCount = 0;
            List<String> errors = new ArrayList<>();

            for (Long agentId : request.getAgentIds()) {
                try {
                    agentService.activateCapability(agentId, request.getPolicyCode() , request.getPolicyData());
                    successCount++;
                } catch (Exception e) {
                    errors.add("Agent " + agentId + ": " + e.getMessage());
                }
            }

            String message = String.format("Policy activated for %d agents", successCount);
            if (!errors.isEmpty()) {
                message += ". Errors: " + String.join("; ", errors);
            }

            log.info("✅ {} - Success: {}, Errors: {}", request.getPolicyCode(), successCount, errors.size());
            return ResponseEntity.ok(new ApiResponse<>(true, message));
        } catch (Exception e) {
            log.error("❌ Failed to assign policy {}: {}", request.getPolicyCode(), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to assign policy: " + e.getMessage()));
        }
    }

    @PostMapping("/deactivate-protection")
    public ResponseEntity<ApiResponse<String>> deactivateProtectionPolicy(
            @RequestBody ProtectionAssignmentRequest request,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            int successCount = 0;
            List<String> errors = new ArrayList<>();

            for (Long agentId : request.getAgentIds()) {
                try {
                    agentService.deactivateCapability(agentId, request.getPolicyCode());
                    successCount++;
                } catch (Exception e) {
                    errors.add("Agent " + agentId + ": " + e.getMessage());
                }
            }

            String message = String.format("Policy deactivated for %d agents", successCount);
            if (!errors.isEmpty()) {
                message += ". Errors: " + String.join("; ", errors);
            }

            return ResponseEntity.ok(new ApiResponse<>(true, message));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to deactivate policy: " + e.getMessage()));
        }
    }

    @GetMapping("/agents/{agentId}/capabilities")
    public ResponseEntity<ApiResponse<Map<String, List<PolicyCapabilityDTO>>>> getAgentCapabilities(
            @PathVariable Long agentId,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            Map<String, List<PolicyCapabilityDTO>> capabilitiesByCategory =
                    agentService.getCapabilitiesByCategory(agentId);

            return ResponseEntity.ok(new ApiResponse<>(true, "Agent capabilities retrieved", capabilitiesByCategory));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to get agent capabilities: " + e.getMessage()));
        }
    }

//    @GetMapping("/agent-policies/{agentId}")
//    public ResponseEntity<ApiResponse<List<Policy>>> getAgentPolicies(@PathVariable Long agentId, HttpSession session) {
//        if (!isAdminAuthenticated(session)) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(new ApiResponse<>(false, "Admin access required"));
//        }
//
//        List<Policy> policies = policyService.getAgentPolicies(agentId);
//        return ResponseEntity.ok(new ApiResponse<>(true, "Agent policies retrieved", policies));
//    }

    @GetMapping("/alerts/pending")
    public ResponseEntity<ApiResponse<List<AlertDTO>>> getPendingAlerts(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        List<AlertDTO> alerts = alertService.getPendingAlerts();
        return ResponseEntity.ok(new ApiResponse<>(true, "Pending alerts retrieved", alerts));
    }

    // ADD THIS NEW ENDPOINT to get ALL alerts for the "Alerts" tab
    @GetMapping("/alerts/all")
    public ResponseEntity<ApiResponse<List<AlertDTO>>> getAllAlerts(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>(false, "Admin access required"));
        }
        List<AlertDTO> alerts = alertService.getAllAlerts();
        return ResponseEntity.ok(new ApiResponse<>(true, "All alerts retrieved", alerts));
    }

    @GetMapping("/agents-with-capability/{policyCode}")
    public ResponseEntity<ApiResponse<List<AgentPolicyStatusDTO>>> getAgentsWithCapability(
            @PathVariable String policyCode,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }
        try {
            // Call the new service method
            List<AgentPolicyStatusDTO> agentStatuses = agentService.getAgentPolicyStatuses(policyCode);
            return ResponseEntity.ok(new ApiResponse<>(true, "Agents retrieved successfully", agentStatuses));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to get agents: " + e.getMessage()));
        }
    }

    @PostMapping("/alerts/{alertId}/decision")
    public ResponseEntity<ApiResponse<AlertDTO>> handleAlertDecision(
            @PathVariable Long alertId,
            @RequestParam String decision,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        AlertDTO updatedAlert = alertService.handleDecision(alertId, decision);
        return ResponseEntity.ok(new ApiResponse<>(true, "Decision processed", updatedAlert));
    }

    @PostMapping("/alerts/create-test")
    public ResponseEntity<ApiResponse<Alert>> createTestAlert(
            @RequestParam Long agentId,
            @RequestParam String alertType,
            @RequestParam String description,
            @RequestParam String deviceInfo,
            @RequestParam String fileDetails,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        User agent = userService.findById(agentId)
                .orElseThrow(() -> new RuntimeException("Agent not found"));

        Alert alert = alertService.createAlert(agent, alertType, description, deviceInfo, fileDetails);
        return ResponseEntity.ok(new ApiResponse<>(true, "Test alert created", alert));
    }

    // THIS ENDPOINT for the Pie Chart
    @GetMapping("/stats/alerts-by-severity")
    public ResponseEntity<ApiResponse<List<AlertStatsDTO>>> getAlertsBySeverity(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>(false, "Admin access required"));
        }
        List<AlertStatsDTO> stats = alertService.getAlertSummaryBySeverity();
        return ResponseEntity.ok(new ApiResponse<>(true, "Alert stats by severity retrieved", stats));
    }

    //THIS ENDPOINT for the Bar Chart
    @GetMapping("/stats/alerts-by-date")
    public ResponseEntity<ApiResponse<List<AlertsByDateDTO>>> getAlertsByDate(HttpSession session) {
        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>(false, "Admin access required"));
        }
        List<AlertsByDateDTO> stats = alertService.getAlertSummaryByDate();
        return ResponseEntity.ok(new ApiResponse<>(true, "Alert stats by date retrieved", stats));
    }

    // ADD THIS NEW ENDPOINT
    @PostMapping("/update-policy-data")
    public ResponseEntity<ApiResponse<String>> updatePolicyData(
            @RequestBody UpdatePolicyDataRequest request,
            HttpSession session) {

        if (!isAdminAuthenticated(session)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>(false, "Admin access required"));
        }

        try {
            agentService.updatePolicyData(request.getAgentId(), request.getPolicyCode(), request.getPolicyData());
            return ResponseEntity.ok(new ApiResponse<>(true, "Policy data updated successfully"));
        } catch (Exception e) {
            log.error("❌ Failed to update policy data: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to update data: " + e.getMessage()));
        }
    }

//    @GetMapping("/debug/assignments")
//    public ResponseEntity<ApiResponse<Map<String, Object>>> debugPolicyAssignments(HttpSession session) {
//        if (!isAdminAuthenticated(session)) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(new ApiResponse<>(false, "Admin access required"));
//        }
//
//        try {
//            Map<String, Object> debugInfo = new HashMap<>();
//
//            List<PolicyAssignment> allAssignments = policyService.getAllPolicyAssignments();
//            debugInfo.put("totalAssignments", allAssignments.size());
//            debugInfo.put("assignments", allAssignments);
//
//            List<User> agents = userService.getAllAgents();
//            List<Map<String, Object>> agentAssignments = new ArrayList<>();
//
//            for (User agent : agents) {
//                Map<String, Object> agentInfo = new HashMap<>();
//                agentInfo.put("agentId", agent.getId());
//                agentInfo.put("username", agent.getUsername());
//                agentInfo.put("policyAssignmentsCount",
//                        agent.getPolicyAssignments() != null ? agent.getPolicyAssignments().size() : 0);
//                agentInfo.put("policyAssignments", agent.getPolicyAssignments());
//                agentAssignments.add(agentInfo);
//            }
//
//            debugInfo.put("agents", agentAssignments);
//
//            return ResponseEntity.ok(new ApiResponse<>(true, "Debug info retrieved", debugInfo));
//
//        } catch (Exception e) {
//            return ResponseEntity.badRequest()
//                    .body(new ApiResponse<>(false, "Debug failed: " + e.getMessage()));
//        }
//    }

    private Policy convertToPolicy(AgentCapability capability, User agent) {
        Policy policy = new Policy();
        policy.setId(capability.getId()); // Use capability ID
        policy.setPolicyCode(capability.getCapabilityCode());
        policy.setName(capability.getName() + " - " + agent.getHostname());
        policy.setDescription(capability.getDescription());
        policy.setCategory(capability.getCategory());
        policy.setPolicyType(capability.getAction() + "_" + capability.getCategory());
        policy.setAction(capability.getAction());
        policy.setTarget(capability.getTarget());
        policy.setSeverity(capability.getSeverity());
        policy.setIsActive(capability.getIsActive());

        // Store agent info for the frontend
        policy.setAgentId(agent.getId());
        policy.setAgentHostname(agent.getHostname());

        return policy;
    }


    private boolean isAdminAuthenticated(HttpSession session) {
        User currentUser = (User) session.getAttribute("currentUser");
        return currentUser != null && currentUser.getRole() == User.UserRole.ADMIN;
    }

    @Data
    public static class CreateAgentRequest {
        private String hostname;
        private String macAddress;
        private String username;
        private String password;

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getHostname() { return hostname; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        public String getMacAddress() { return macAddress; }
        public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
    }

    @Data
    public static class ProtectionAssignmentRequest {
        private String policyCode;
        private List<Long> agentIds;
        private String policyData;

        public String getPolicyData() {
            return policyData;
        }

        public void setPolicyData(String policyData) {
            this.policyData = policyData;
        }

        public List<Long> getAgentIds() { return agentIds; }
        public void setAgentIds(List<Long> agentIds) { this.agentIds = agentIds; }
        public String getPolicyCode() { return policyCode; }
        public void setPolicyCode(String policyCode) { this.policyCode = policyCode; }
    }
}