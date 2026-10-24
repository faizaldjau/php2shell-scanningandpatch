<!-- Tab 1: Remote Blackbox Security Audit -->
<div id="tab-audit" class="tab-content space-y-6">
    <!-- Main Interactive Card -->
    <div class="glass-panel p-6 rounded-2xl border border-white/10 shadow-2xl relative overflow-hidden">
        <!-- Background subtle glow decoration -->
        <div class="absolute -right-16 -top-16 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div class="relative z-10">
            <!-- Header Section -->
            <div class="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-white/5 gap-4">
                <div>
                    <h2 class="text-xl font-bold text-white flex items-center space-x-2.5">
                        <span class="w-2.5 h-2.5 rounded-full bg-cyan-400 radar-pulse"></span>
                        <span>Remote Blackbox Security Audit</span>
                    </h2>
                    <p class="text-xs text-slate-400 mt-1">
                        Memindai kerentanan <strong>PHP2Shell (CVE-2026-109618 & CVE-2026-109619)</strong> via probe multipart bertingkat & evaluasi <strong>OWASP Top 10</strong>.
                    </p>
                </div>

                <!-- Mode Switcher (Single Target vs Bulk File) -->
                <div class="inline-flex p-1 rounded-xl bg-slate-900/90 border border-white/10 self-start md:self-auto">
                    <button type="button" id="mode-btn-single" onclick="Scanner.switchInputMode('single')" class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition shadow-sm flex items-center space-x-1.5">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
                        <span>Target Tunggal</span>
                    </button>
                    <button type="button" id="mode-btn-bulk" onclick="Scanner.switchInputMode('bulk')" class="px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition flex items-center space-x-1.5">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                        <span>Unggah Daftar (.txt)</span>
                    </button>
                </div>
            </div>

            <!-- Form -->
            <form id="scan-form" class="mt-6 space-y-5">
                <!-- Mode 1: Single Target Input Field -->
                <div id="input-container-single" class="space-y-2">
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Domain / URL / IP Server Sasaran
                    </label>
                    <div class="relative flex items-center">
                        <div class="absolute left-3.5 text-slate-500 pointer-events-none">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                        </div>
                        <input type="text" name="target_url" id="target_url" placeholder="https://sipp.pn-contoh.go.id atau http://192.168.1.50" class="w-full bg-[#080d19] border border-white/10 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono shadow-inner transition">
                    </div>
                    <p class="text-[11px] text-slate-400">Dukungan: HTTPS/HTTP, nama domain FQDN satker pengadilan, atau alamat IP langsung.</p>
                </div>

                <!-- Direct Origin IP / Bypass WAF Target (Optional) -->
                <div id="input-container-origin" class="space-y-1.5 p-3.5 bg-slate-900/40 rounded-xl border border-white/5">
                    <div class="flex items-center justify-between">
                        <label class="block text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
                            <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                            <span>Direct Origin IP / Bypass Cloudflare (Opsional)</span>
                        </label>
                        <span class="text-[10px] text-cyan-400 font-mono bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">Bypass WAF Edge</span>
                    </div>
                    <div class="relative flex items-center">
                        <div class="absolute left-3 text-slate-500 pointer-events-none">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                        </div>
                        <input type="text" name="origin_ip" id="origin_ip" placeholder="Contoh: 103.xxx.xxx.xxx atau 192.168.1.50 (Kosongkan jika ingin scan normal via Cloudflare)" class="w-full bg-[#080d19] border border-white/10 rounded-xl pl-9 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono shadow-inner transition">
                    </div>
                    <p class="text-[10px] text-slate-400">Koneksi TCP/TLS ditembakkan langsung ke IP fisik origin server Anda dengan TLS SNI & Host domain asli.</p>
                </div>

                <!-- Mode 2: Bulk Upload Field (Hidden by default) -->
                <div id="input-container-bulk" class="hidden space-y-2">
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Unggah Berkas Teks Daftar Sasaran (.txt)
                    </label>
                    <div class="border-2 border-dashed border-white/10 hover:border-cyan-500/50 rounded-2xl p-6 text-center bg-[#080d19]/60 transition group cursor-pointer relative">
                        <input type="file" name="target_file" id="target_file" accept=".txt" onchange="Scanner.handleFileSelected(this)" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer">
                        <div class="flex flex-col items-center justify-center space-y-2">
                            <div class="w-12 h-12 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center group-hover:scale-110 transition">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                            </div>
                            <div class="text-xs text-slate-300 font-medium">
                                <span class="text-cyan-400 underline">Klik untuk memilih file</span> atau seret file <code class="text-white">.txt</code> ke sini
                            </div>
                            <p id="file-selected-name" class="text-[11px] text-slate-400">Maksimal ukuran berkas 2MB (satu URL/domain per baris)</p>
                        </div>
                    </div>
                </div>

                <!-- Scan Parameters & Options -->
                <div class="p-4 rounded-xl bg-slate-900/50 border border-white/5 grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-[11px] font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Aturan SAPI Target</label>
                        <select name="sapi" class="w-full bg-[#080d19] border border-white/10 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500">
                            <option value="auto">Auto (mod_php + PHP-FPM)</option>
                            <option value="fpm">PHP-FPM SAPI</option>
                            <option value="mod_php">Apache mod_php</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-[11px] font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Batas Waktu Timeout</label>
                        <select name="timeout" class="w-full bg-[#080d19] border border-white/10 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono">
                            <option value="15">15 Detik (Cepat / Responsif)</option>
                            <option value="30" selected>30 Detik (Standar Rekomendasi)</option>
                            <option value="60">60 Detik (Jaringan Lambat / VPN)</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-[11px] font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Custom Path (Opsional)</label>
                        <input type="text" name="custom_path" placeholder="/index.php" class="w-full bg-[#080d19] border border-white/10 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono">
                    </div>
                </div>

                <!-- Submit Button Bar -->
                <div class="flex items-center justify-between pt-1">
                    <div class="text-xs text-slate-400 flex items-center space-x-1.5">
                        <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                        <span>Audit Non-Destruktif (Bebas Risiko Shell Crash Permanen)</span>
                    </div>

                    <button type="submit" id="btn-submit-scan" class="px-6 py-3 bg-gradient-to-r from-cyan-600 via-teal-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-bold text-xs sm:text-sm rounded-xl shadow-lg glow-cyan flex items-center space-x-2 transition hover-lift">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <span>Mulai Audit Keamanan</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Live Scanning Progress Box (Hidden initially) -->
    <div id="scan-progress-box" class="hidden glass-panel p-5 rounded-2xl border border-cyan-500/30 shadow-2xl space-y-3">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between text-xs gap-2">
            <div class="flex items-center space-x-2.5">
                <div class="w-2.5 h-2.5 rounded-full bg-cyan-400 radar-pulse"></div>
                <span id="scan-current-host" class="font-mono text-cyan-300 font-semibold truncate max-w-md">Menghubungi target...</span>
            </div>
            <div class="flex items-center space-x-2">
                <span class="text-slate-400">Progres Pemindaian:</span>
                <span id="scan-progress-text" class="font-mono text-white font-bold px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-[11px]">0%</span>
            </div>
        </div>
        <div class="w-full bg-black/60 rounded-full h-2.5 overflow-hidden border border-white/5">
            <div id="scan-progress-bar" class="bg-gradient-to-r from-cyan-500 via-teal-400 to-emerald-400 h-2.5 rounded-full transition-all duration-300" style="width: 0%"></div>
        </div>
    </div>

    <!-- Results Section -->
    <div class="glass-panel rounded-2xl border border-white/10 shadow-2xl overflow-hidden">
        <div class="px-6 py-4.5 border-b border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div class="flex items-center space-x-3">
                <h3 class="text-sm font-bold text-white flex items-center space-x-2">
                    <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
                    <span>Hasil Audit Keamanan Target</span>
                </h3>
                <span id="results-count" class="px-2.5 py-0.5 rounded-full bg-slate-800 text-cyan-300 text-xs font-mono font-semibold border border-white/5">0 Sasaran</span>
            </div>

            <div class="flex items-center space-x-2">
                <button onclick="Scanner.exportResultsJson()" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700 text-slate-200 border border-white/10 transition flex items-center space-x-1.5">
                    <svg class="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                    <span>Ekspor Hasil Laporan (JSON)</span>
                </button>
            </div>
        </div>

        <!-- Empty State -->
        <div id="results-empty" class="py-16 text-center text-slate-500">
            <div class="w-16 h-16 rounded-2xl bg-slate-900/60 border border-white/5 flex items-center justify-center mx-auto mb-3 text-slate-600">
                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            </div>
            <p class="text-sm text-slate-300 font-semibold">Belum Ada Hasil Audit</p>
            <p class="text-xs text-slate-500 mt-1 max-w-sm mx-auto">Masukkan domain/IP sasaran atau unggah file daftar host di atas untuk memulai pemindaian mendalam.</p>
        </div>

        <!-- Table View -->
        <div id="results-table-container" class="hidden overflow-x-auto">
            <table class="w-full text-left border-collapse text-xs">
                <thead>
                    <tr class="bg-slate-950/70 border-b border-white/5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                        <th class="px-5 py-3.5">Sasaran Host / Domain</th>
                        <th class="px-5 py-3.5">PHP2Shell (CVE-2026-109618/19)</th>
                        <th class="px-5 py-3.5">Kepatuhan OWASP</th>
                        <th class="px-5 py-3.5">Tingkat Risiko Total</th>
                        <th class="px-5 py-3.5 text-right">Aksi Audit</th>
                    </tr>
                </thead>
                <tbody id="results-tbody" class="divide-y divide-white/5 text-slate-300">
                    <!-- Injected by scanner.js -->
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Modal Detail Bukti Teknis & Checklist OWASP -->
<div id="detail-modal" class="fixed inset-0 z-50 bg-black/80 backdrop-blur-md hidden flex items-center justify-center p-4">
    <div class="glass-panel border border-white/10 rounded-2xl shadow-2xl max-w-2xl w-full p-6 max-h-[88vh] flex flex-col relative animate-cyber-fade">
        <div class="flex justify-between items-center pb-3 border-b border-white/10">
            <div class="flex items-center space-x-2">
                <div class="w-2 h-2 rounded-full bg-cyan-400"></div>
                <h3 class="text-sm font-bold text-white uppercase tracking-wider">Rincian Hasil Audit & Bukti Teknis</h3>
            </div>
            <button onclick="Scanner.closeDetailModal()" class="w-7 h-7 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition">&times;</button>
        </div>
        <div id="modal-content" class="overflow-y-auto flex-grow my-4 space-y-4 pr-1">
            <!-- Injected by scanner.js -->
        </div>
        <div class="pt-3 border-t border-white/10 flex justify-end">
            <button onclick="Scanner.closeDetailModal()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition">
                Tutup Jendela
            </button>
        </div>
    </div>
</div>
