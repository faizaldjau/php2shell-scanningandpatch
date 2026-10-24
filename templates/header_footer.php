<?php
/**
 * Modern Cybersecurity Layout - Header & Footer
 */

function renderHeader(string $title = "PHP2Shell & OWASP Top 10 Security Suite"): void {
?>
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?></title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        cyber: {
                            950: '#060911',
                            900: '#0c1220',
                            800: '#131c31',
                            700: '#1e293b',
                            cyan: '#06b6d4',
                            emerald: '#10b981',
                            rose: '#f43f5e',
                            amber: '#f59e0b'
                        }
                    }
                }
            }
        }
    </script>
    <!-- Custom CSS -->
    <link rel="stylesheet" href="assets/css/app.css">
</head>
<body class="bg-[#060911] text-slate-100 min-h-screen flex flex-col antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
    <!-- Top Glassmorphic Navigation -->
    <header class="sticky top-0 z-50 bg-[#0c1220]/80 backdrop-blur-xl border-b border-white/5 transition-all">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-20">
                <!-- Brand & Logo -->
                <div class="flex items-center space-x-3.5">
                    <div class="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-600 via-teal-500 to-emerald-400 p-[1px] shadow-lg glow-cyan">
                        <div class="w-full h-full bg-[#0c1220] rounded-[11px] flex items-center justify-center">
                            <span class="font-mono font-black text-xl bg-gradient-to-tr from-cyan-400 to-emerald-400 bg-clip-text text-transparent">&Phi;</span>
                        </div>
                    </div>
                    <div>
                        <div class="flex items-center space-x-2">
                            <h1 class="text-base sm:text-lg font-bold tracking-tight text-white font-mono flex items-center">
                                PHP2SHELL<span class="text-cyan-400 ml-1">DEFENSE</span>
                            </h1>
                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                                CVE-2026-109618/19
                            </span>
                        </div>
                        <p class="text-xs text-slate-400 flex items-center space-x-1.5 mt-0.5">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 radar-pulse mr-1"></span>
                            <span>SIPP Court Hardening & OWASP Top 10 Suite</span>
                        </p>
                    </div>
                </div>

                <!-- Navigation Tabs (Segmented Control) -->
                <nav class="hidden md:flex p-1 rounded-xl bg-slate-900/90 border border-white/5 shadow-inner">
                    <button id="tab-btn-audit" onclick="App.setTab('audit')" class="nav-tab-btn px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 shadow-sm transition-all duration-200 flex items-center space-x-2">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                        <span>Remote Audit</span>
                    </button>
                    <button id="tab-btn-ssh" onclick="App.setTab('ssh')" class="nav-tab-btn px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-200 flex items-center space-x-2">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                        <span>SSH In-Host Audit</span>
                    </button>
                    <button id="tab-btn-mitigation" onclick="App.setTab('mitigation')" class="nav-tab-btn px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-200 flex items-center space-x-2">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                        <span>Generator Remediasi</span>
                    </button>
                    <button id="tab-btn-demo" onclick="App.setTab('demo')" class="nav-tab-btn px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-200 flex items-center space-x-2">
                        <svg class="w-3.5 h-3.5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        <span>Demo Penetrasi</span>
                    </button>
                    <button id="tab-btn-hardening" onclick="App.setTab('hardening')" class="nav-tab-btn px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-200 flex items-center space-x-2">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                        <span>Standar OWASP</span>
                    </button>
                </nav>

                <!-- Status Badge -->
                <div class="flex items-center space-x-2">
                    <span class="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Laragon Active
                    </span>
                </div>
            </div>

            <!-- Mobile Navigation Strip -->
            <div class="flex md:hidden overflow-x-auto py-2 space-x-1 border-t border-white/5 scrollbar-none">
                <button onclick="App.setTab('audit')" class="px-3 py-1.5 text-xs whitespace-nowrap text-cyan-300 font-semibold">Remote Audit</button>
                <button onclick="App.setTab('ssh')" class="px-3 py-1.5 text-xs whitespace-nowrap text-slate-400">SSH In-Host</button>
                <button onclick="App.setTab('mitigation')" class="px-3 py-1.5 text-xs whitespace-nowrap text-slate-400">Remediasi</button>
                <button onclick="App.setTab('demo')" class="px-3 py-1.5 text-xs whitespace-nowrap text-rose-400 font-medium">Demo Penetrasi</button>
                <button onclick="App.setTab('hardening')" class="px-3 py-1.5 text-xs whitespace-nowrap text-slate-400">OWASP Hardening</button>
            </div>
        </div>
    </header>

    <!-- Top Key Metrics Banner -->
    <section class="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6 pb-2">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
            <div class="glass-panel p-3.5 rounded-xl border border-white/5 hover-lift">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Tingkat Ancaman</div>
                <div class="text-base sm:text-lg font-bold font-mono text-rose-400 mt-0.5 flex items-center">
                    <span>9.8 CRITICAL</span>
                    <span class="text-[10px] ml-1.5 px-1 rounded bg-rose-500/20 text-rose-300">CVSS v3</span>
                </div>
                <div class="text-[10px] text-slate-500 mt-0.5">Pre-Auth Core Memory RCE</div>
            </div>

            <div class="glass-panel p-3.5 rounded-xl border border-white/5 hover-lift">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Jangkauan Celah</div>
                <div class="text-base sm:text-lg font-bold font-mono text-amber-400 mt-0.5">PHP 5.4 — 8.5.11</div>
                <div class="text-[10px] text-slate-500 mt-0.5">Mencakup 14 Tahun Kode Core</div>
            </div>

            <div class="glass-panel p-3.5 rounded-xl border border-white/5 hover-lift">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Fokus Infrastruktur</div>
                <div class="text-base sm:text-lg font-bold font-mono text-cyan-400 mt-0.5">SIPP Pengadilan</div>
                <div class="text-[10px] text-slate-500 mt-0.5">Ubuntu 24.04, Alma & CentOS 7</div>
            </div>

            <div class="glass-panel p-3.5 rounded-xl border border-white/5 hover-lift">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Standar Audit</div>
                <div class="text-base sm:text-lg font-bold font-mono text-emerald-400 mt-0.5">OWASP WSTG v4.2</div>
                <div class="text-[10px] text-slate-500 mt-0.5">BSSN / ID-SIRTII Aligned</div>
            </div>
        </div>
    </section>

    <!-- Notification Toast Container -->
    <div id="toast-container" class="fixed bottom-5 right-5 z-50 space-y-2.5 max-w-sm w-full pointer-events-none"></div>

    <!-- Main Container -->
    <main class="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5">
<?php
}

function renderFooter(): void {
?>
    </main>

    <!-- Sleek Modern Footer -->
    <footer class="bg-[#090e1a]/80 backdrop-blur border-t border-white/5 py-6 mt-12 text-xs text-slate-400">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div class="flex items-center space-x-3">
                <span class="font-mono font-bold text-white tracking-wider">PHP2SHELL<span class="text-cyan-400">DEFENSE</span></span>
                <span class="text-slate-600">&bull;</span>
                <span>Security Operations Center Toolkit</span>
                <span class="text-slate-600">&bull;</span>
                <span class="text-slate-500">Standar BSSN / ID-SIRTII & OWASP</span>
            </div>
            <div class="flex items-center space-x-4 text-slate-400">
                <span class="flex items-center"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Laragon Engine 8.3</span>
                <span class="text-slate-600">&bull;</span>
                <span class="font-mono text-cyan-300">Localhost Ready</span>
            </div>
        </div>
    </footer>

    <!-- Global App Scripts -->
    <script src="assets/js/app.js"></script>
    <script src="assets/js/scanner.js"></script>
    <script src="assets/js/ssh_auditor.js"></script>
</body>
</html>
<?php
}
