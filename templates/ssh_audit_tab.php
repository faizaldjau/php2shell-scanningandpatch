<!-- Tab 2: In-Host SSH Audit & Remediation -->
<div id="tab-ssh" class="tab-content hidden space-y-6">
    <!-- Top Banner -->
    <div class="glass-panel p-6 rounded-2xl border border-white/10 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-16 -top-16 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div class="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
                <h2 class="text-xl font-bold text-white flex items-center space-x-2.5">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 radar-pulse"></span>
                    <span>Authorized In-Host SSH Audit & Automated Hardening</span>
                </h2>
                <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                    Melakukan audit internal server dengan hak akses sah via SSH. Terintegrasi penuh dengan <strong>Surat Edaran Ditjen Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026</strong> untuk otomatisasi pemasangan paket patch resmi biner CentOS 7 SIPP (<code class="text-cyan-300 font-mono">s.id/cvemari</code>) serta pendeteksian jejak penyusupan (*Indicators of Compromise*).
                </p>
            </div>
            <div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                SIPP Badilum MA-RI Standard
            </div>
        </div>
    </div>

    <!-- Grid Form & Terminal -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- SSH Form Panel (5 cols) -->
        <div class="lg:col-span-5 glass-panel p-6 rounded-2xl border border-white/10 shadow-xl space-y-4 flex flex-col justify-between">
            <div>
                <div class="flex items-center justify-between pb-3 border-b border-white/5 mb-4">
                    <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                        <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                        <span>Parameter Akses SSH Server SIPP</span>
                    </h3>
                    <span class="text-[10px] text-slate-500 font-mono">Port Standar: 22</span>
                </div>

                <form id="ssh-form" class="space-y-3.5">
                    <div class="grid grid-cols-3 gap-2.5">
                        <div class="col-span-2">
                            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Host / IP Server SIPP</label>
                            <input type="text" name="host" placeholder="192.168.1.50 atau sipp.pn-*.go.id" required class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono shadow-inner transition">
                        </div>
                        <div>
                            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Port SSH</label>
                            <input type="number" name="port" value="22" required class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono shadow-inner transition">
                        </div>
                    </div>

                    <div class="grid grid-cols-2 gap-2.5">
                        <div>
                            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Username</label>
                            <input type="text" name="user" value="root" required class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono shadow-inner transition">
                        </div>
                        <div>
                            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Password</label>
                            <input type="password" name="password" placeholder="••••••••" class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500 shadow-inner transition">
                        </div>
                    </div>

                    <div>
                        <label class="block text-[11px] font-semibold text-slate-400 mb-1">Sudo Password (Opsional)</label>
                        <input type="password" name="sudo_password" placeholder="Hanya jika user bukan root" class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500 shadow-inner transition">
                    </div>

                    <div>
                        <label class="block text-[11px] font-semibold text-slate-400 mb-1">Atau Gunakan Private Key (.pem / .id_rsa)</label>
                        <textarea name="private_key" rows="2" placeholder="-----BEGIN RSA/OPENSSH PRIVATE KEY-----" class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-[10px] text-slate-300 font-mono placeholder-slate-700 focus:outline-none focus:border-emerald-500 shadow-inner transition"></textarea>
                    </div>

                    <div>
                        <label class="block text-[11px] font-semibold text-slate-400 mb-1">Zona Waktu Pengadilan (date.timezone)</label>
                        <select name="timezone" id="ssh-timezone-select" class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500 font-sans shadow-inner transition">
                            <option value="">-- Pertahankan Pengaturan Server Saat Ini --</option>
                            <option value="Asia/Makassar">Asia/Makassar (WITA — Gorontalo, Sulsel, Bali, NTB, NTT, Kaltim, Kaltara)</option>
                            <option value="Asia/Jakarta">Asia/Jakarta (WIB — Jawa, Sumatera, Kalbar, Kalteng)</option>
                            <option value="Asia/Jayapura">Asia/Jayapura (WIT — Maluku, Papua)</option>
                            <option value="UTC">UTC (Standar Internasional)</option>
                        </select>
                        <p class="text-[10px] text-slate-500 mt-1">Pilih sesuai wilayah hukum satker Anda jika ingin disetel saat Hardening/Patch.</p>
                    </div>

                    <div class="pt-2">
                        <button type="submit" id="btn-ssh-audit" class="w-full py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs rounded-xl shadow-lg glow-emerald flex items-center justify-center space-x-2 transition hover-lift">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                            <span>Jalankan Audit SSH Internal (Read-Only)</span>
                        </button>
                    </div>
                </form>
            </div>

            <!-- Zero-Persistence Privacy Banner -->
            <div class="mt-4 p-3.5 rounded-xl bg-slate-900/60 border border-white/5 text-[11px] text-slate-400 space-y-1">
                <div class="font-semibold text-slate-300 flex items-center space-x-1.5">
                    <svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    <span>Kebijakan Zero-Persistence Kredensial</span>
                </div>
                <p>Password dan private key tidak pernah dicatat ke database atau disk lokal Laragon. Koneksi ditransmisikan aman melalui pipa memori proses.</p>
            </div>
        </div>

        <!-- Terminal & Results Panel (7 cols) -->
        <div class="lg:col-span-7 space-y-5">
            <!-- In-Host Summary Cards (Hidden initially) -->
            <div id="ssh-audit-results" class="hidden glass-panel p-5 rounded-2xl border border-white/10 shadow-xl space-y-4">
                <div class="flex items-center justify-between pb-3 border-b border-white/5">
                    <div class="flex items-center space-x-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                        <h4 class="text-xs font-bold text-white uppercase tracking-wider">Telemetri & Status Internal Server</h4>
                    </div>
                    <span id="ssh-res-os" class="text-xs font-mono px-2.5 py-0.5 rounded-full bg-slate-800 text-cyan-300 border border-white/5">Linux</span>
                </div>

                <!-- Alert Card: Surat Edaran Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026 -->
                <div id="ssh-mari-banner" class="hidden p-4 rounded-xl border space-y-2">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-2 font-bold text-xs" id="ssh-mari-banner-title">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                            <span>Surat Ditjen Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026</span>
                        </div>
                        <a href="https://drive.google.com/open?id=1XKdEt3faVS8YPbSPaiaU_YsXTsg56Mul&usp=drive_copy" target="_blank" rel="noopener" class="text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 underline flex items-center space-x-1">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            <span>Tonton Video Panduan</span>
                        </a>
                    </div>
                    <p id="ssh-mari-banner-desc" class="text-xs leading-relaxed"></p>
                </div>

                <!-- Compromise Assessment Alert Box (IoC) -->
                <div id="ssh-comp-banner" class="hidden p-4 rounded-xl border space-y-2">
                    <div class="flex items-center space-x-2 font-bold text-xs" id="ssh-comp-title">
                        <span>Pemeriksaan Jejak Penyusupan (Indicators of Compromise)</span>
                    </div>
                    <div id="ssh-comp-content" class="text-xs leading-relaxed space-y-1.5"></div>
                </div>

                <div class="grid grid-cols-2 sm:grid-cols-3 gap-3.5 text-xs">
                    <div class="p-3 bg-black/40 rounded-xl border border-white/5">
                        <span class="text-slate-400 block text-[10px] uppercase font-semibold">Biner PHP Aktif</span>
                        <span id="ssh-res-php" class="font-mono text-white font-bold text-xs truncate block mt-0.5">Memuat...</span>
                    </div>
                    <div class="p-3 bg-black/40 rounded-xl border border-white/5">
                        <span class="text-slate-400 block text-[10px] uppercase font-semibold">Status Patch Keamanan</span>
                        <div id="ssh-res-mari-status" class="mt-0.5">Memuat...</div>
                    </div>
                    <div class="p-3 bg-black/40 rounded-xl border border-white/5">
                        <span class="text-slate-400 block text-[10px] uppercase font-semibold">Zona Waktu (date.timezone)</span>
                        <div id="ssh-res-timezone" class="mt-0.5">Memuat...</div>
                    </div>
                    <div class="p-3 bg-black/40 rounded-xl border border-white/5">
                        <span class="text-slate-400 block text-[10px] uppercase font-semibold">session.upload_progress</span>
                        <div id="ssh-res-upload-progress" class="mt-1">Memuat...</div>
                    </div>
                    <div class="p-3 bg-black/40 rounded-xl border border-white/5">
                        <span class="text-slate-400 block text-[10px] uppercase font-semibold">max_input_nesting_level</span>
                        <div id="ssh-res-nesting" class="font-mono text-xs font-bold mt-1">Memuat...</div>
                    </div>
                    <div class="p-3 bg-black/40 rounded-xl border border-white/5">
                        <span class="text-slate-400 block text-[10px] uppercase font-semibold">Layanan Web / FPM Aktif</span>
                        <div id="ssh-res-services" class="font-mono text-cyan-300 text-xs font-bold truncate mt-1">Memuat...</div>
                    </div>
                </div>

                <!-- CVE-2026-115560 4-Condition Assessment Card -->
                <div class="p-3.5 bg-black/50 rounded-xl border border-white/10 space-y-2">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-2">
                            <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
                            <span class="text-xs font-bold text-white uppercase tracking-wider">Audit Spesifik CVE-2026-115560 (Advisori 23 Okt 2026)</span>
                        </div>
                        <span id="ssh-cve115560-badge" class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400">EVALUASI...</span>
                    </div>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                        <div class="p-2 bg-slate-900/80 rounded-lg border border-white/5">
                            <span class="text-slate-500 block text-[10px]">1. Initial Handler:</span>
                            <span id="cve-cond-handler" class="font-mono text-cyan-300 font-semibold">-</span>
                        </div>
                        <div class="p-2 bg-slate-900/80 rounded-lg border border-white/5">
                            <span class="text-slate-500 block text-[10px]">2. CI3 App ini_set:</span>
                            <span id="cve-cond-app" class="font-mono text-slate-300 font-semibold">-</span>
                        </div>
                        <div class="p-2 bg-slate-900/80 rounded-lg border border-white/5">
                            <span class="text-slate-500 block text-[10px]">3. session_start():</span>
                            <span id="cve-cond-start" class="font-mono text-slate-300 font-semibold">Tereksekusi</span>
                        </div>
                        <div class="p-2 bg-slate-900/80 rounded-lg border border-white/5">
                            <span class="text-slate-500 block text-[10px]">4. upload_progress:</span>
                            <span id="cve-cond-upload" class="font-mono text-rose-400 font-semibold">-</span>
                        </div>
                    </div>
                    <div id="cve-cond-notes" class="text-[11px] text-slate-400 leading-relaxed pt-1 border-t border-white/5">
                        Menunggu data audit internal...
                    </div>
                </div>

                <!-- Multi-Action Bar for Remediation & Compromise Assessment -->
                <div id="ssh-action-box" class="pt-3 border-t border-white/5 space-y-3">
                    <div class="text-[11px] font-semibold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                        <span>Aksi Mitigasi & Deteksi Jejak Penyusupan:</span>
                    </div>

                    <!-- Instant Full Remediation Primary Action Button -->
                    <button type="button" id="btn-ssh-instant-patch" onclick="SshAuditor.showPatchConfirmationModal('instant')" class="w-full py-3 px-4 bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 hover:from-emerald-500 hover:via-teal-500 hover:to-cyan-500 text-white font-bold text-xs rounded-xl shadow-xl glow-emerald flex items-center justify-center space-x-2 transition hover-lift">
                        <svg class="w-4 h-4 text-emerald-200 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        <span>⚡ Terapkan Patch Keamanan Instan (Full Remediasi + Hardening)</span>
                    </button>

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <!-- Button 1A: Official MA-RI Patch Installer (CentOS 7 only) -->
                        <button type="button" id="btn-ssh-mari-patch" onclick="SshAuditor.showPatchConfirmationModal('mari')" class="hidden w-full py-2.5 px-3 bg-gradient-to-r from-amber-600 to-amber-700 hover:from-amber-500 hover:to-amber-600 text-white font-bold text-xs rounded-xl shadow-lg flex items-center justify-center space-x-1.5 transition hover-lift">
                            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                            <span class="truncate">Pasang Patch MA-RI</span>
                        </button>

                        <!-- Button 1B: Distro-native Package Upgrade (Ubuntu/Debian APT or AlmaLinux DNF) -->
                        <button type="button" id="btn-ssh-distro-upgrade" onclick="SshAuditor.showPatchConfirmationModal('distro')" class="hidden w-full py-2.5 px-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-bold text-xs rounded-xl shadow-lg flex items-center justify-center space-x-1.5 transition hover-lift">
                            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            <span id="btn-ssh-distro-upgrade-label" class="truncate">Update Keamanan (APT)</span>
                        </button>

                        <!-- Button 2: Config Hardening -->
                        <button type="button" id="btn-ssh-harden" onclick="SshAuditor.showPatchConfirmationModal('harden')" class="w-full py-2.5 px-3 bg-gradient-to-r from-slate-800 to-slate-700 hover:from-slate-700 hover:to-slate-600 text-slate-200 border border-white/10 font-bold text-xs rounded-xl shadow flex items-center justify-center space-x-1.5 transition hover-lift">
                            <svg class="w-4 h-4 shrink-0 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                            <span class="truncate">Kunci php.ini</span>
                        </button>

                        <!-- Button 3: Compromise Assessment (IoC Check) -->
                        <button type="button" id="btn-ssh-compromise" onclick="SshAuditor.executeCompromiseCheck()" class="w-full py-2.5 px-3 bg-gradient-to-r from-purple-600 to-indigo-700 hover:from-purple-500 hover:to-indigo-600 text-white font-bold text-xs rounded-xl shadow-lg flex items-center justify-center space-x-1.5 transition hover-lift">
                            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                            <span class="truncate">Cek Jejak Penyusupan</span>
                        </button>
                    </div>

                    <!-- Emergency Incident Response Quarantine Action Button (Triggerable when compromise is detected or manually) -->
                    <button type="button" id="btn-ssh-quarantine" onclick="SshAuditor.showQuarantineModal()" class="w-full py-2.5 px-4 bg-gradient-to-r from-rose-800 via-red-700 to-rose-900 hover:from-rose-700 hover:via-red-600 hover:to-rose-800 text-white font-bold text-xs rounded-xl shadow-lg border border-rose-500/30 flex items-center justify-center space-x-2 transition hover-lift">
                        <svg class="w-4 h-4 text-rose-300 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        <span>🚨 Tindakan Tanggap Darurat: Karantina Sesi Beracun & Netralkan Webshell</span>
                    </button>
                </div>
            </div>

            <!-- Terminal Output Console Window -->
            <div class="glass-panel rounded-2xl border border-white/10 shadow-2xl overflow-hidden">
                <!-- Mac-style Window Title Bar -->
                <div class="bg-[#0c1220] px-4 py-3 border-b border-white/5 flex items-center justify-between">
                    <div class="flex items-center space-x-2">
                        <span class="terminal-dot dot-red"></span>
                        <span class="terminal-dot dot-yellow"></span>
                        <span class="terminal-dot dot-green"></span>
                        <span class="text-xs text-slate-400 font-mono ml-2">ssh-terminal@laragon:~$</span>
                    </div>
                    <button onclick="SshAuditor.clearTerminal()" class="text-[11px] text-slate-400 hover:text-white transition">Bersihkan Log</button>
                </div>
                <!-- Terminal Output Text -->
                <pre id="ssh-terminal-log" class="p-4 text-xs text-emerald-400 font-mono h-72 overflow-y-auto whitespace-pre-wrap leading-relaxed bg-[#050811] selection:bg-emerald-500/30">
[+] Konsol Audit SSH siap. Masukkan kredensial server di samping dan tekan 'Jalankan Audit SSH Internal'.
                </pre>
            </div>
        </div>
    </div>
</div>

<!-- Modal Konfirmasi Rencana Patch Keamanan Server -->
<div id="patch-confirm-modal" class="fixed inset-0 z-50 bg-black/85 backdrop-blur-md hidden flex items-center justify-center p-4">
    <div class="glass-panel border border-white/10 rounded-2xl shadow-2xl max-w-2xl w-full p-6 max-h-[92vh] flex flex-col relative animate-cyber-fade">
        <!-- Modal Header -->
        <div class="flex justify-between items-center pb-3 border-b border-white/10">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center justify-center shadow-lg">
                    <svg class="w-5 h-5 text-emerald-400 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <div>
                    <h3 id="patch-modal-title" class="text-sm font-bold text-white uppercase tracking-wider">Konfirmasi Rencana Penerapan Patch Keamanan</h3>
                    <p class="text-[11px] text-slate-400">Verifikasi daftar tindakan teknis yang akan dieksekusi secara otomatis ke server target</p>
                </div>
            </div>
            <button onclick="SshAuditor.closePatchModal()" class="w-7 h-7 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition">&times;</button>
        </div>

        <!-- Modal Scrollable Content -->
        <div id="patch-modal-body" class="overflow-y-auto flex-grow my-4 space-y-4 pr-1 text-xs">
            <!-- Target Summary Card -->
            <div class="p-3.5 bg-slate-900/60 rounded-xl border border-white/5 space-y-2">
                <div class="flex items-center justify-between pb-2 border-b border-white/5">
                    <span class="text-slate-400 text-[11px] font-semibold uppercase">Target Host:</span>
                    <span id="patch-modal-host" class="font-mono text-cyan-300 font-bold">127.0.0.1</span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                        <span class="text-slate-500 block">Sistem Operasi:</span>
                        <span id="patch-modal-os" class="text-white font-medium">Ubuntu Linux</span>
                    </div>
                    <div>
                        <span class="text-slate-500 block">Biner PHP Aktif:</span>
                        <span id="patch-modal-php" class="text-white font-mono font-medium truncate block">PHP 7.4.33</span>
                    </div>
                </div>
            </div>

            <!-- Execution Plan Checklist -->
            <div class="space-y-2.5">
                <div class="flex items-center justify-between">
                    <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                        <span>Daftar Tindakan Teknis yang Akan Dilakukan:</span>
                    </h4>
                    <span id="patch-modal-badge" class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">REMEDIASI PENUH</span>
                </div>

                <div class="space-y-2" id="patch-modal-checklist">
                    <!-- Dynamic Checklist Items Injected by JS -->
                </div>
            </div>

            <!-- Caution Advisory Callout -->
            <div class="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-start space-x-2.5 text-amber-200">
                <svg class="w-4 h-4 text-amber-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <div class="text-[11px] leading-relaxed">
                    <strong>Pemberitahuan Sistem:</strong> Eksekusi ini akan memuat ulang (*restart*) layanan web server dan PHP-FPM yang aktif untuk menerapkan perubahan secara instan. Proses berlangsung terisolasi tanpa memodifikasi basis data perkara.
                </div>
            </div>
        </div>

        <!-- Modal Footer Actions -->
        <div class="pt-3 border-t border-white/10 flex items-center justify-between">
            <button type="button" onclick="SshAuditor.closePatchModal()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl transition">
                Batal / Tutup
            </button>
            <button type="button" id="btn-modal-execute-patch" onclick="SshAuditor.confirmAndExecutePatch()" class="px-5 py-2.5 bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 hover:from-emerald-500 hover:via-teal-500 hover:to-cyan-500 text-white font-bold text-xs rounded-xl shadow-lg glow-emerald flex items-center space-x-2 transition hover-lift">
                <svg class="w-4 h-4 text-emerald-200" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                <span id="btn-modal-execute-label">Ya, Terapkan Patch Keamanan Sekarang</span>
            </button>
        </div>
    </div>
</div>

<!-- Modal Konfirmasi Tanggap Darurat Karantina Berkas -->
<div id="quarantine-confirm-modal" class="fixed inset-0 z-50 bg-black/85 backdrop-blur-md hidden flex items-center justify-center p-4">
    <div class="glass-panel border border-rose-500/30 rounded-2xl shadow-2xl max-w-xl w-full p-6 relative animate-cyber-fade">
        <div class="flex justify-between items-center pb-3 border-b border-rose-500/20">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center justify-center shadow-lg">
                    <svg class="w-5 h-5 text-rose-400 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                </div>
                <div>
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">Konfirmasi Tanggap Darurat & Karantina Insiden</h3>
                    <p class="text-[11px] text-rose-300/80">Eradikasi ancaman aktif & isolasi jejak kompromi di server target</p>
                </div>
            </div>
            <button onclick="SshAuditor.closeQuarantineModal()" class="w-7 h-7 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition">&times;</button>
        </div>

        <div class="my-4 space-y-3 text-xs">
            <div class="p-3 bg-rose-950/40 rounded-xl border border-rose-500/30 text-rose-200 text-xs leading-relaxed">
                Tindakan ini akan mengeksekusi prosedur tanggap darurat forensik otomatis pada server:
            </div>
            <div class="space-y-2">
                <div class="flex items-start space-x-2.5 p-2.5 bg-slate-900/60 rounded-xl border border-white/5">
                    <div class="w-5 h-5 rounded-md bg-rose-500/20 text-rose-400 text-xs flex items-center justify-center shrink-0 font-bold">1</div>
                    <div class="text-[11px] text-slate-300">
                        <strong>Isolasi Berkas Sesi Beracun:</strong> Memindahkan file sesi di <code>/tmp/sess_*</code> atau <code>/var/lib/php/session/</code> yang memuat injeksi serialisasi ke <code>/var/quarantine/sessions/</code> dengan hak akses <code>chmod 000</code>.
                    </div>
                </div>
                <div class="flex items-start space-x-2.5 p-2.5 bg-slate-900/60 rounded-xl border border-white/5">
                    <div class="w-5 h-5 rounded-md bg-rose-500/20 text-rose-400 text-xs flex items-center justify-center shrink-0 font-bold">2</div>
                    <div class="text-[11px] text-slate-300">
                        <strong>Karantina Webshell Upload:</strong> Menonaktifkan berkas PHP asing di folder berkas perkara SIPP dengan me-rename menjadi <code>*.quarantined</code> dan menguncinya dengan <code>chmod 000</code>.
                    </div>
                </div>
                <div class="flex items-start space-x-2.5 p-2.5 bg-slate-900/60 rounded-xl border border-white/5">
                    <div class="w-5 h-5 rounded-md bg-rose-500/20 text-rose-400 text-xs flex items-center justify-center shrink-0 font-bold">3</div>
                    <div class="text-[11px] text-slate-300">
                        <strong>Matikan Proses Reverse Shell:</strong> Menghabisi (*kill -9*) proses shell interaktif liar (<code>nc</code>, <code>bash -i</code>, python socket) yang sedang berjalan.
                    </div>
                </div>
            </div>
        </div>

        <div class="pt-3 border-t border-white/10 flex items-center justify-between">
            <button type="button" onclick="SshAuditor.closeQuarantineModal()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl transition">
                Batal
            </button>
            <button type="button" id="btn-modal-execute-quarantine" onclick="SshAuditor.executeQuarantine()" class="px-5 py-2.5 bg-gradient-to-r from-rose-700 to-red-600 hover:from-rose-600 hover:to-red-500 text-white font-bold text-xs rounded-xl shadow-lg glow-rose flex items-center space-x-2 transition hover-lift">
                <svg class="w-4 h-4 text-rose-200" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <span>Ya, Eksekusi Karantina & Pembersihan Sekarang</span>
            </button>
        </div>
    </div>
</div>
