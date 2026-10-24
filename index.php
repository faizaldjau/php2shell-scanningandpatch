<?php
/**
 * PHP2Shell & OWASP Top 10 Security Audit Suite
 * 
 * Main Entry Point for Web Interface
 * Running on Laragon Windows (http://localhost/proj-php2shell)
 */

require_once __DIR__ . '/templates/header_footer.php';

renderHeader("PHP2Shell & OWASP Top 10 Security Audit Suite - Mahkamah Agung SIPP Standard");

// 1. Remote Blackbox Audit Tab
require_once __DIR__ . '/templates/audit_tab.php';

// 2. In-Host SSH Audit & Remediation Tab
require_once __DIR__ . '/templates/ssh_audit_tab.php';

// 3. Technical Guidance & Config Generator Tab
require_once __DIR__ . '/templates/mitigation_tab.php';

// 4. Safe PoC Penetration Simulation Demo Tab
require_once __DIR__ . '/templates/demo_tab.php';

// 5. Standar OWASP & Hardening Principles Tab
require_once __DIR__ . '/templates/hardening_tab.php';

renderFooter();
