package com.ma.dlp.controller;

import com.ma.dlp.dto.*;
import com.ma.dlp.model.AgentCapability;
import com.ma.dlp.model.Alert;
import com.ma.dlp.model.Policy;
import com.ma.dlp.model.User;
import com.ma.dlp.service.AgentService;
import com.ma.dlp.service.AlertService;
import com.ma.dlp.service.UserService;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/agent")
public class AgentController {

    @Autowired
    private AgentService agentService;

    @Autowired
    private AlertService alertService;

    @Autowired
    private UserService userService;

    private static final Logger log = LoggerFactory.getLogger(AgentController.class);

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> registerAgent(@RequestBody AgentRegistrationRequest request) {
        try {
            String pendingId = String.valueOf(agentService.registerAgent(request.getHostname(), request.getMacAddress()));
            return ResponseEntity.ok(new ApiResponse<>(true,
                    "Registration submitted for admin approval. Pending ID: " + pendingId));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Registration failed: " + e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AgentService.AgentAuthResponse>> agentLogin(@RequestBody AgentLoginRequest request) {
        try {
            AgentService.AgentAuthResponse response;

            if (request.getHostname() != null && request.getMacAddress() != null) {
                response = agentService.authenticateAgent(request.getHostname(), request.getMacAddress());
            } else if (request.getUsername() != null && request.getPassword() != null) {
                response = agentService.loginWithCredentials(request.getUsername(), request.getPassword());
            } else {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse<>(false, "Invalid login request"));
            }

            return ResponseEntity.ok(new ApiResponse<>(true, "Agent authenticated", response));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Authentication failed: " + e.getMessage()));
        }
    }

    @PostMapping("/capabilities")
    public ResponseEntity<ApiResponse<String>> reportCapabilities(
            @RequestHeader("Authorization") String token,
            @RequestBody CapabilityReportRequest request) {

        if (!agentService.validateToken(token, request.getAgentId())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Invalid token"));
        }

        try {
            agentService.saveAgentCapabilities(request.getAgentId(), request.getCapabilities());
            return ResponseEntity.ok(new ApiResponse<>(true, "Capabilities reported successfully"));
        } catch (Exception e) {
            log.error("❌ Failed to report capabilities for agent {}: {}",
                    request.getAgentId(), e.getMessage() , e);
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to report capabilities: " + e.getMessage()));
        }
    }

    @GetMapping("/active-policies")
    public ResponseEntity<ApiResponse<AgentPoliciesResponse>> getActivePolicies(
            @RequestHeader("Authorization") String token,
            @RequestParam Long agentId) {

        // 1. You check if the token is valid
        if (!agentService.validateToken(token, agentId)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Invalid token"));
        }

        try {

            // 2. NEW: You check the agent's status in the database
            User agent = userService.findById(agentId)
                    .orElseThrow(() -> new RuntimeException("Agent not found"));
            if (agent.getStatus() != User.UserStatus.ACTIVE) {
                log.warn("Agent {} is not active, rejecting policy request.", agentId);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new ApiResponse<>(false, "Agent account is not active."));
            }

            // Get active capabilities and convert to policies
            List<AgentCapability> activeCapabilities = agentService.getActiveCapabilities(agentId);
            List<Policy> policies = convertCapabilitiesToPolicies(activeCapabilities);

            AgentPoliciesResponse response = new AgentPoliciesResponse();
            response.setAgentId(agentId);
            response.setPolicies(policies);
            response.setTimestamp(System.currentTimeMillis());

            log.info("📋 Returning {} active policies to agent {}", policies.size(), agentId);

            return ResponseEntity.ok(new ApiResponse<>(true, "Active policies retrieved", response));
        } catch (Exception e) {
            log.error("❌ Failed to get active policies for agent {}: {}", agentId, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to get active policies: " + e.getMessage()));
        }
    }



//    @GetMapping("/policies")
//    public ResponseEntity<ApiResponse<AgentPoliciesResponse>> getAgentPolicies(
//            @RequestHeader("Authorization") String token,
//            @RequestParam Long agentId) {
//
//        if (!agentService.validateToken(token, agentId)) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
//                    .body(new ApiResponse<>(false, "Invalid token"));
//        }
//
//        try {
//            List<Policy> policies = policyService.getAgentPolicies(agentId);
//
//            AgentPoliciesResponse response = new AgentPoliciesResponse();
//            response.setAgentId(agentId);
//            response.setPolicies(policies);
//            response.setTimestamp(System.currentTimeMillis());
//
//            return ResponseEntity.ok(new ApiResponse<>(true, "Policies retrieved", response));
//        } catch (Exception e) {
//            return ResponseEntity.badRequest()
//                    .body(new ApiResponse<>(false, "Failed to get policies: " + e.getMessage()));
//        }
//    }

    @PostMapping("/alerts")
    public ResponseEntity<ApiResponse<String>> submitAlert(
            @RequestHeader("Authorization") String token,
            @RequestBody AgentAlertRequest alertRequest) {

        if (!agentService.validateToken(token, alertRequest.getAgentId())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Invalid token"));
        }

        try {
            User agent = userService.findById(alertRequest.getAgentId())
                    .orElseThrow(() -> new RuntimeException("Agent not found"));

            Alert alert = new Alert();
            alert.setAgent(agent);
            alert.setAlertType(alertRequest.getAlertType());
            alert.setDescription(alertRequest.getDescription());
            alert.setDeviceInfo(alertRequest.getDeviceInfo());
            alert.setFileDetails(alertRequest.getFileDetails());
            alert.setSeverity(alertRequest.getSeverity());
            alert.setStatus("PENDING");
            alert.setActionTaken(alertRequest.getActionTaken());

            alertService.saveAlert(alert);

            return ResponseEntity.ok(new ApiResponse<>(true, "Alert received successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to save alert: " + e.getMessage()));
        }
    }

    @PostMapping("/heartbeat")
    public ResponseEntity<ApiResponse<String>> heartbeat(
            @RequestHeader("Authorization") String token,
            @RequestParam Long agentId) {

        // Check 1: Is the token valid?
        if (!agentService.validateToken(token, agentId)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Invalid token"));
        }

        try {
            // Check 2: Is the agent's account ACTIVE?
            User agent = userService.findById(agentId)
                    .orElseThrow(() -> new RuntimeException("Agent not found with ID: " + agentId));

            if (agent.getStatus() != User.UserStatus.ACTIVE) {
                log.warn("Agent {} is not active, rejecting heartbeat.", agentId);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new ApiResponse<>(false, "Agent account is not active."));
            }

            // If both checks pass, proceed
            agentService.updateHeartbeat(agentId);
            return ResponseEntity.ok(new ApiResponse<>(true, "Heartbeat received"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Heartbeat failed: " + e.getMessage()));
        }
    }

    @PostMapping("/usb-alert")
    public ResponseEntity<ApiResponse<String>> submitUSBAlert(
            @RequestHeader("Authorization") String token,
            @RequestBody USBAlertRequest usbAlert) {

        if (!agentService.validateToken(token, usbAlert.getAgentId())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "Invalid token"));
        }

        try {
            User agent = userService.findById(usbAlert.getAgentId())
                    .orElseThrow(() -> new RuntimeException("Agent not found"));

            String description = String.format(
                    "USB Device Detected: %s - %d files analyzed, %d file types, %d suspicious files. Total size: %d bytes",
                    usbAlert.getDeviceInfo().getDriveLetter(),
                    usbAlert.getFileAnalysis().getTotalFiles(),
                    usbAlert.getFileAnalysis().getFileTypes().size(),
                    usbAlert.getFileAnalysis().getSuspiciousFiles().size(),
                    usbAlert.getFileAnalysis().getTotalSize()
            );

            String fileDetails = String.format(
                    "File Types: %s | Suspicious Files: %s",
                    usbAlert.getFileAnalysis().getFileTypes().toString(),
                    usbAlert.getFileAnalysis().getSuspiciousFiles().toString()
            );

            Alert alert = new Alert();
            alert.setAgent(agent);
            alert.setAlertType("USB_INSERTION");
            alert.setDescription(description);
            alert.setDeviceInfo(usbAlert.getDeviceInfo().toString());
            alert.setFileDetails(fileDetails);
            alert.setSeverity("HIGH");
            alert.setStatus("PENDING");
            alert.setActionTaken(usbAlert.getActionTaken());

            alertService.saveAlert(alert);

            return ResponseEntity.ok(new ApiResponse<>(true, "USB alert received"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(false, "Failed to process USB alert: " + e.getMessage()));
        }
    }

    private List<Policy> convertCapabilitiesToPolicies(List<AgentCapability> capabilities) {
        return capabilities.stream()
                .map(this::convertCapabilityToPolicy)
                .toList();
    }

    private Policy convertCapabilityToPolicy(AgentCapability capability) {
        Policy policy = new Policy();
        policy.setPolicyCode(capability.getCapabilityCode());
        policy.setName(capability.getName());
        policy.setDescription(capability.getDescription());
        policy.setCategory(capability.getCategory());
        policy.setPolicyType(capability.getAction() + "_" + capability.getCategory());
        policy.setAction(capability.getAction());
        policy.setTarget(capability.getTarget());
        policy.setSeverity(capability.getSeverity());
        policy.setIsActive(true); // These are all active since we filtered for active capabilities

        return policy;
    }

}


