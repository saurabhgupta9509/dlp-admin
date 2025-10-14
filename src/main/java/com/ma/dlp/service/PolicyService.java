//package com.ma.dlp.service;
//
//import com.ma.dlp.Repository.PolicyAssignmentRepository;
//import com.ma.dlp.Repository.PolicyRepository;
//import com.ma.dlp.model.Policy;
//import com.ma.dlp.model.PolicyAssignment;
//import com.ma.dlp.model.User;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;
//import jakarta.annotation.PostConstruct;
//import java.util.*;
//
//@Service
//public class PolicyService {
//
//    @Autowired
//    private PolicyRepository policyRepository;
//
//    @Autowired
//    private PolicyAssignmentRepository policyAssignmentRepository;
//
//    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);
//
//    public Policy createPolicy(Policy policy) {
//        return policyRepository.save(policy);
//    }
//
//    public List<Policy> getAllPolicies() {
//        return policyRepository.findAll();
//    }
//
//    public List<Policy> getPoliciesByCategory(String category) {
//        return policyRepository.findByCategory(category);
//    }
//
//    public Optional<Policy> getPolicyById(Long id) {
//        return policyRepository.findById(id);
//    }
//
//    public void deletePolicy(Long id) {
//        policyRepository.deleteById(id);
//    }
//
//    public List<Policy> getAgentPolicies(Long agentId) {
//        List<PolicyAssignment> assignments = policyAssignmentRepository.findByUserIdAndStatus(agentId, "ACTIVE");
//        return assignments.stream()
//                .map(PolicyAssignment::getPolicy)
//                .toList();
//    }
//
//    @PostConstruct
//    public void initPrebuiltPolicies() {
//        createPrebuiltPolicies();
//    }
//
//    private void createPrebuiltPolicies() {
//        if (policyRepository.count() > 0) {
//            System.out.println("✅ Prebuilt policies already exist");
//            return;
//        }
//
//        System.out.println("🔄 Creating prebuilt policies...");
//
//        createAndSavePolicy("USB-001", "USB Device Block", "USB", "DEVICE_BLOCK", "BLOCK", "ALL", "Block all USB storage devices", "HIGH");
//        createAndSavePolicy("USB-002", "USB File Monitor", "USB", "FILE_MONITOR", "MONITOR", "ALL", "Monitor all file operations on USB devices", "MEDIUM");
//        createAndSavePolicy("USB-003", "Executable Block on USB", "USB", "FILE_BLOCK", "BLOCK", "exe,bat,msi,ps1", "Block executable files on USB devices", "HIGH");
//        createAndSavePolicy("USB-004", "USB Read Only", "USB", "DEVICE_CONTROL", "ALLOW", "READ_ONLY", "Allow read-only access to USB devices", "MEDIUM");
//
//        System.out.println("✅ Prebuilt USB policies created successfully");
//    }
//
//    private void createAndSavePolicy(String policyCode, String name, String category, String policyType,
//                                     String action, String target, String description, String severity) {
//        try {
//            Policy policy = new Policy();
//            policy.setPolicyCode(policyCode);
//            policy.setName(name);
//            policy.setCategory(category);
//            policy.setPolicyType(policyType);
//            policy.setAction(action);
//            policy.setTarget(target);
//            policy.setDescription(description);
//            policy.setSeverity(severity);
//            policy.setIsActive(true);
//
//            policyRepository.save(policy);
//            System.out.println("✅ Created policy: " + policyCode + " - " + name);
//        } catch (Exception e) {
//            System.out.println("❌ Failed to create policy " + policyCode + ": " + e.getMessage());
//        }
//    }
//
//    public Policy getPrebuiltPolicyByCode(String policyCode) {
//        return policyRepository.findByPolicyCode(policyCode)
//                .orElseThrow(() -> new RuntimeException("Prebuilt policy not found: " + policyCode));
//    }
//
//    public List<Policy> getPrebuiltPoliciesByCategory(String category) {
//        List<Policy> policies = policyRepository.findByCategoryAndIsActiveTrue(category);
//        System.out.println("📋 Found " + policies.size() + " policies for category: " + category);
//        return policies;
//    }
//
//    public void assignPolicyToAgent(User agent, String policyCode) {
//        try {
//            Policy policy = getPrebuiltPolicyByCode(policyCode);
//
//            boolean alreadyAssigned = policyAssignmentRepository.existsByUserIdAndPolicyId(agent.getId(), policy.getId());
//            if (alreadyAssigned) {
//                log.info("ℹ️ Policy '{}' already assigned to agent: {}", policy.getName(), agent.getUsername());
//                return;
//            }
//
//            PolicyAssignment assignment = new PolicyAssignment();
//            assignment.setUser(agent);
//            assignment.setPolicy(policy);
//            assignment.setStatus("ACTIVE");
//            assignment.setAssignedAt(new Date());
//            assignment.setEffectiveFrom(new Date());
//
//            PolicyAssignment savedAssignment = policyAssignmentRepository.save(assignment);
//
//            if (agent.getPolicyAssignments() == null) {
//                agent.setPolicyAssignments(new ArrayList<>());
//            }
//
//            agent.getPolicyAssignments().add(savedAssignment);
//
//            log.info("✅ Policy '{}' successfully assigned to agent: {} (Assignment ID: {})",
//                    policy.getName(), agent.getUsername(), savedAssignment.getId());
//
//        } catch (Exception e) {
//            log.error("❌ Failed to assign policy '{}' to agent {}: {}",
//                    policyCode, agent.getUsername(), e.getMessage());
//            throw new RuntimeException("Policy assignment failed: " + e.getMessage());
//        }
//    }
//
//    public List<PolicyAssignment> getAllPolicyAssignments() {
//        return policyAssignmentRepository.findAll();
//    }
//}
//
//package com.ma.dlp.service;
//
//import com.ma.dlp.Repository.PolicyAssignmentRepository;
//import com.ma.dlp.Repository.PolicyRepository;
//import com.ma.dlp.model.Policy;
//import com.ma.dlp.model.PolicyAssignment;
//import com.ma.dlp.model.User;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;
//import jakarta.annotation.PostConstruct;
//import java.util.*;
//
//@Service
//public class PolicyService {
//
//    @Autowired
//    private PolicyRepository policyRepository;
//
//    @Autowired
//    private PolicyAssignmentRepository policyAssignmentRepository;
//
//    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);
//
//    // Add this method to get all pre-built policies
//    public Map<String, List<Policy>> getPreBuiltProtectionPolicies() {
//        Map<String, List<Policy>> policiesByCategory = new HashMap<>();
//
//        // Get all active policies and group by category
//        List<Policy> allPolicies = policyRepository.findByIsActiveTrue();
//
//        for (Policy policy : allPolicies) {
//            String category = policy.getCategory();
//            if (category != null) {
//                policiesByCategory
//                        .computeIfAbsent(category, k -> new ArrayList<>())
//                        .add(policy);
//            }
//        }
//
//        log.info("📋 Returning {} policy categories with total {} policies",
//                policiesByCategory.size(), allPolicies.size());
//
//        return policiesByCategory;
//    }
//
//    public Policy createPolicy(Policy policy) {
//        return policyRepository.save(policy);
//    }
//
//    public List<Policy> getAllPolicies() {
//        return policyRepository.findAll();
//    }
//
//    public List<Policy> getPoliciesByCategory(String category) {
//        return policyRepository.findByCategory(category);
//    }
//
//    public Optional<Policy> getPolicyById(Long id) {
//        return policyRepository.findById(id);
//    }
//
//    public void deletePolicy(Long id) {
//        policyRepository.deleteById(id);
//    }
//
//    public List<Policy> getAgentPolicies(Long agentId) {
//        List<PolicyAssignment> assignments = policyAssignmentRepository.findByUserIdAndStatus(agentId, "ACTIVE");
//        return assignments.stream()
//                .map(PolicyAssignment::getPolicy)
//                .toList();
//    }
//
//    @PostConstruct
//    public void initPrebuiltPolicies() {
//        createPrebuiltPolicies();
//    }
//
//    private void createPrebuiltPolicies() {
//        if (policyRepository.count() > 0) {
//            log.info("✅ Prebuilt policies already exist");
//            return;
//        }
//
//        log.info("🔄 Creating prebuilt policies...");
//
//        // USB Protection Policies
//        createAndSavePolicy("USB-001", "USB Device Block", "USB", "DEVICE_BLOCK", "BLOCK", "ALL", "Block all USB storage devices", "HIGH");
//        createAndSavePolicy("USB-002", "USB File Monitor", "USB", "FILE_MONITOR", "MONITOR", "ALL", "Monitor all file operations on USB devices", "MEDIUM");
//        createAndSavePolicy("USB-003", "Executable Block on USB", "USB", "FILE_BLOCK", "BLOCK", "exe,bat,msi,ps1", "Block executable files on USB devices", "HIGH");
//        createAndSavePolicy("USB-004", "USB Read Only", "USB", "DEVICE_CONTROL", "ALLOW", "READ_ONLY", "Allow read-only access to USB devices", "MEDIUM");
//
//        // Network Protection Policies
//        createAndSavePolicy("NET-001", "Block Cloud Uploads", "NETWORK", "NETWORK_BLOCK", "BLOCK", "cloud_uploads", "Block file uploads to cloud services", "HIGH");
//        createAndSavePolicy("NET-002", "Monitor Network Shares", "NETWORK", "NETWORK_MONITOR", "MONITOR", "network_shares", "Monitor file transfers to network shares", "MEDIUM");
//
//        // File Protection Policies
//        createAndSavePolicy("FILE-001", "Block Sensitive File Types", "FILE", "FILE_BLOCK", "BLOCK", "sensitive_extensions", "Block access to sensitive file types", "HIGH");
//        createAndSavePolicy("FILE-002", "Monitor File Access", "FILE", "FILE_MONITOR", "MONITOR", "confidential_files", "Monitor access to confidential files", "MEDIUM");
//
//        log.info("✅ Prebuilt policies created successfully");
//    }
//
//    private void createAndSavePolicy(String policyCode, String name, String category, String policyType,
//                                     String action, String target, String description, String severity) {
//        try {
//            Policy policy = new Policy();
//            policy.setPolicyCode(policyCode);
//            policy.setName(name);
//            policy.setCategory(category);
//            policy.setPolicyType(policyType);
//            policy.setAction(action);
//            policy.setTarget(target);
//            policy.setDescription(description);
//            policy.setSeverity(severity);
//            policy.setIsActive(true);
//
//            policyRepository.save(policy);
//            log.info("✅ Created policy: {} - {}", policyCode, name);
//        } catch (Exception e) {
//            log.error("❌ Failed to create policy {}: {}", policyCode, e.getMessage());
//        }
//    }
//
//    public Policy getPrebuiltPolicyByCode(String policyCode) {
//        return policyRepository.findByPolicyCode(policyCode)
//                .orElseThrow(() -> new RuntimeException("Prebuilt policy not found: " + policyCode));
//    }
//
//    public List<Policy> getPrebuiltPoliciesByCategory(String category) {
//        List<Policy> policies = policyRepository.findByCategoryAndIsActiveTrue(category);
//        log.info("📋 Found {} policies for category: {}", policies.size(), category);
//
//        // Debug: log the policy codes found
//        if (policies.isEmpty()) {
//            log.warn("❌ No policies found for category: {}. Available categories: {}",
//                    category, getAvailableCategories());
//        } else {
//            policies.forEach(p -> log.debug("   - {}: {}", p.getPolicyCode(), p.getName()));
//        }
//
//        return policies;
//    }
//
//    // Helper method to see what categories exist
//    private List<String> getAvailableCategories() {
//        return policyRepository.findDistinctCategories();
//    }
//
//    public void assignPolicyToAgent(User agent, String policyCode) {
//        try {
//            Policy policy = getPrebuiltPolicyByCode(policyCode);
//
//            boolean alreadyAssigned = policyAssignmentRepository.existsByUserIdAndPolicyId(agent.getId(), policy.getId());
//            if (alreadyAssigned) {
//                log.info("ℹ️ Policy '{}' already assigned to agent: {}", policy.getName(), agent.getUsername());
//                return;
//            }
//
//            PolicyAssignment assignment = new PolicyAssignment();
//            assignment.setUser(agent);
//            assignment.setPolicy(policy);
//            assignment.setStatus("ACTIVE");
//            assignment.setAssignedAt(new Date());
//            assignment.setEffectiveFrom(new Date());
//
//            PolicyAssignment savedAssignment = policyAssignmentRepository.save(assignment);
//
//            if (agent.getPolicyAssignments() == null) {
//                agent.setPolicyAssignments(new ArrayList<>());
//            }
//
//            agent.getPolicyAssignments().add(savedAssignment);
//
//            log.info("✅ Policy '{}' successfully assigned to agent: {} (Assignment ID: {})",
//                    policy.getName(), agent.getUsername(), savedAssignment.getId());
//
//        } catch (Exception e) {
//            log.error("❌ Failed to assign policy '{}' to agent {}: {}",
//                    policyCode, agent.getUsername(), e.getMessage());
//            throw new RuntimeException("Policy assignment failed: " + e.getMessage());
//        }
//    }
//
//    public List<PolicyAssignment> getAllPolicyAssignments() {
//        return policyAssignmentRepository.findAll();
//    }
//}

package com.ma.dlp.service;

import com.ma.dlp.Repository.PolicyRepository;
import com.ma.dlp.model.Policy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PolicyService {

    @Autowired
    private PolicyRepository policyRepository;

    /**
     * Finds and returns all master Policy objects that belong to a specific category.
     * This is used by the AdminController to populate the policy wizard on the dashboard.
     * @param category The name of the category (e.g., "USB", "NETWORK").
     * @return A list of policies matching the category.
     */
    public List<Policy> getPoliciesByCategory(String category) {
        return policyRepository.findByCategory(category);
    }
}
