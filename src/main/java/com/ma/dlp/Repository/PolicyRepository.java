// PolicyRepository.java
package com.ma.dlp.Repository;

import com.ma.dlp.model.Policy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, Long> {

    List<Policy> findByCategory(String category);

    // ✅ FIXED: Use proper field name
    List<Policy> findByCategoryAndIsActiveTrue(String category);

    Optional<Policy> findByPolicyCode(String policyCode);

    // ✅ FIXED: Use proper field name
    List<Policy> findByIsActiveTrue();

    // ✅ ADD: Find by category and active status
    List<Policy> findByCategoryAndIsActive(String category, Boolean isActive);

    @Query("SELECT DISTINCT p.category FROM Policy p WHERE p.category IS NOT NULL")
    List<String> findDistinctCategories();
}