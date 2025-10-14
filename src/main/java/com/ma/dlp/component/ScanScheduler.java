//package com.ma.dlp.component;
//
//import com.ma.dlp.service.DiscoveryService;
//import org.springframework.scheduling.annotation.Scheduled;
//import org.springframework.stereotype.Component;
//
//import java.util.List;
//
//@Component
//public class ScanScheduler {
//
////    private final ScanRepository scanRepository;
////    private final DiscoveryService discoveryService;
////    private final PolicyService policyService;
////
////    public ScanScheduler(ScanRepository scanRepository, DiscoveryService discoveryService, PolicyService policyService) {
////        this.scanRepository = scanRepository;
////        this.discoveryService = discoveryService;
////        this.policyService = policyService;
//    }
//
//    // Every 5 minutes:
//    @Scheduled(fixedRate = 300_000)
//    public void pickAndRunScans() {
//        List<Scan> pending = scanRepository.findAll().stream()
//                .filter(s -> "PENDING".equalsIgnoreCase(s.getStatus()))
//                .toList();
//        for (Scan s : pending) {
//            discoveryService.runScan(s, policyService);
//        }
//    }
//}
