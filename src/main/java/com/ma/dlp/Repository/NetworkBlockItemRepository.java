package com.ma.dlp.Repository;

import com.ma.dlp.model.NetworkBlockItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NetworkBlockItemRepository extends JpaRepository<NetworkBlockItem, Long> {

    // Find all items of a specific type (e.g., all DOMAINS)
    List<NetworkBlockItem> findByType(NetworkBlockItem.BlockType type);

    // Find an item by its value to prevent duplicates
    boolean existsByValue(String value);
}