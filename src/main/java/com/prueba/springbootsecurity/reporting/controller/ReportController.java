package com.prueba.springbootsecurity.reporting.controller;

import com.prueba.springbootsecurity.reporting.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService service;

    @GetMapping("/sensitive")
    public String sensitive() {
        return service.generateSensitiveReport();
    }

    @GetMapping("/user")
    public String userReport() {
        return service.generateUserReport();
    }

    @GetMapping("/user/ultraSensible")
    public String ultraSensibleReport() { return service.generateUserReportRead(); }
}
