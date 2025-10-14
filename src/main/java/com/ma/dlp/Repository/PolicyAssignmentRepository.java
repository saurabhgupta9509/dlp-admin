//// PolicyAssignmentRepository.java
//package com.ma.dlp.Repository;
//
//import com.ma.dlp.model.PolicyAssignment;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.Param;
//import org.springframework.stereotype.Repository;
//
//import java.util.List;
//
//
//@Repository
//public interface PolicyAssignmentRepository extends JpaRepository<PolicyAssignment, Long> {
//    List<PolicyAssignment> findByUserId(Long userId);
//    List<PolicyAssignment> findByUserIdAndStatus(Long userId, String status);
//
//    boolean existsByUserIdAndPolicyId(Long userId, Long policyId);
//
//    @Query("SELECT pa FROM PolicyAssignment pa WHERE pa.user.id = :userId AND pa.status = 'ACTIVE'")
//    List<PolicyAssignment> findActiveAssignmentsByUserId(@Param("userId") Long userId);
//
//}