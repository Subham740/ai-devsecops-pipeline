package com.hcltech.devsecops;

import java.io.IOException;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    private static final String DEMO_PASSWORD = "change-me-in-production";

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @GetMapping("/admin/ping")
    public Map<String, String> ping(@RequestParam String host) throws IOException {
        Runtime.getRuntime().exec("ping " + host);
        return Map.of("status", "started", "passwordHint", DEMO_PASSWORD);
    }
}
