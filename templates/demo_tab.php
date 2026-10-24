<!-- Tab 5: Safe PoC Penetration Simulation & Urgent Alert Demo -->
<div id="tab-demo" class="tab-content hidden space-y-6">
    <!-- Top Banner -->
    <div class="glass-panel p-6 rounded-2xl border border-white/10 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-16 -top-16 w-64 h-64 bg-rose-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div class="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
                <h2 class="text-xl font-bold text-white flex items-center space-x-2.5">
                    <span class="w-2.5 h-2.5 rounded-full bg-rose-500 radar-pulse"></span>
                    <span>Modul Simulasi & Demo Penetrasi Aman (Safe PoC Trigger)</span>
                </h2>
                <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                    Membuktikan kerentanan <strong>PHP2Shell (CVE-2026-109618 & CVE-2026-109619)</strong> secara deterministik dan non-destruktif untuk keperluan demonstrasi kesiapan sistem tanpa menanamkan backdoor atau merusak server.
                </p>
            </div>
            <div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
                Safe Verification Mode
            </div>
        </div>
    </div>

    <!-- Main Simulator Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Input & Configuration Box (5 cols) -->
        <div class="lg:col-span-5 glass-panel p-6 rounded-2xl border border-white/10 shadow-xl space-y-5 flex flex-col justify-between">
            <div class="space-y-4">
                <div class="flex items-center justify-between pb-3 border-b border-white/5">
                    <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                        <svg class="w-4 h-4 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        <span>Parameter Target Simulasi</span>
                    </h3>
                    <span class="text-[10px] text-slate-500 font-mono">Zero-Payload</span>
                </div>

                <form id="demo-form" onsubmit="DemoSimulator.runDemo(event)" class="space-y-4">
                    <div>
                        <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                            URL / Host Server Sasaran
                        </label>
                        <div class="relative">
                            <input type="text" id="demo-target-url" placeholder="http://127.0.0.1/proj-php2shell/" value="http://127.0.0.1/proj-php2shell/" class="w-full bg-[#080d19] border border-white/10 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-rose-500 focus:ring-1 focus:ring-rose-500 font-mono shadow-inner transition">
                        </div>
                    </div>

                    <div>
                        <div class="flex items-center justify-between mb-1.5">
                            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                                <span>Direct Origin IP (Bypass Cloudflare / WAF)</span>
                            </label>
                            <span class="text-[10px] text-cyan-400 font-mono">Opsional</span>
                        </div>
                        <input type="text" id="demo-origin-ip" placeholder="Contoh: 103.xxx.xxx.xxx atau 192.168.1.50" class="w-full bg-[#080d19] border border-white/10 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-rose-500 font-mono shadow-inner transition">
                        <p class="text-[10px] text-slate-500 mt-1">Kosongkan jika ingin scan publik normal. Isi IP jika ingin bypass CDN Cloudflare langsung ke server fisik.</p>
                    </div>

                    <!-- Quick Preset Buttons -->
                    <div class="space-y-1.5">
                        <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                            Target Cepat Pengujian:
                        </label>
                        <div class="flex flex-wrap gap-2">
                            <button type="button" onclick="DemoSimulator.setTarget('http://127.0.0.1/proj-php2shell/')" class="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-white/5 transition flex items-center space-x-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                                <span>Localhost (Laragon)</span>
                            </button>
                            <button type="button" onclick="DemoSimulator.setTarget('http://sipplokal.pn-tilamuta.go.id/')" class="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-400 border border-white/5 transition flex items-center space-x-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                                <span>Intranet Pengadilan</span>
                            </button>
                        </div>
                    </div>

                    <!-- Security Assurance Card -->
                    <div class="p-3.5 bg-black/40 border border-white/5 rounded-xl text-xs space-y-1.5 text-slate-400">
                        <div class="flex items-center space-x-1.5 text-slate-300 font-semibold text-[11px]">
                            <svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                            <span>Jaminan Keamanan Simulasi</span>
                        </div>
                        <p class="text-[11px] leading-relaxed">
                            Probe ini <strong>tidak menanam webshell</strong>, tidak mengeksekusi perintah shell OS, dan hanya memverifikasi apakah alokasi Zend heap crash saat parsing multipart.
                        </p>
                    </div>

                    <!-- Submit Button -->
                    <button type="submit" id="btn-run-demo" class="w-full py-3.5 px-4 bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-semibold rounded-xl shadow-lg shadow-rose-950/50 hover:shadow-rose-900/60 transition duration-200 flex items-center justify-center space-x-2 text-xs">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path></svg>
                        <span>Jalankan Simulasi Penetrasi Aman</span>
                    </button>
                </form>
            </div>

            <!-- Footer note -->
            <div class="pt-3 border-t border-white/5 text-[10px] text-slate-500 flex items-center justify-between">
                <span>Metodologi: Assetnote + OpenAI Checker</span>
                <span>Port 80/443 HTTP Handshake</span>
            </div>
        </div>

        <!-- Simulation Results / Alert Canvas (7 cols) -->
        <div class="lg:col-span-7 glass-panel p-6 rounded-2xl border border-white/10 shadow-2xl flex flex-col justify-between space-y-4">
            <!-- Stage Tracker Bar (Visible during scan) -->
            <div id="demo-stage-box" class="hidden p-4 bg-slate-900/60 border border-white/5 rounded-xl space-y-3">
                <div class="flex items-center justify-between text-xs">
                    <span class="font-bold text-white flex items-center space-x-2">
                        <svg class="animate-spin h-3.5 w-3.5 text-rose-400" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                        <span id="demo-stage-text">Tahap 1: Memverifikasi Koneksi Target (Pre-Flight)...</span>
                    </span>
                    <span id="demo-stage-timer" class="font-mono text-[11px] text-slate-400">0.0s</span>
                </div>
                <div class="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                    <div id="demo-stage-bar" class="bg-rose-500 h-1.5 rounded-full transition-all duration-300" style="width: 25%"></div>
                </div>
            </div>

            <!-- Canvas Container -->
            <div id="demo-canvas" class="flex-grow flex flex-col justify-center">
                <!-- Idle State (Default) -->
                <div id="demo-state-idle" class="text-center py-12 px-4 space-y-4">
                    <div class="w-16 h-16 rounded-2xl bg-slate-900 border border-white/10 flex items-center justify-center mx-auto text-slate-500">
                        <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    </div>
                    <div>
                        <h4 class="text-base font-bold text-white">Simulasi Penetrasi Siap Dijalankan</h4>
                        <p class="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                            Masukkan URL target di sisi kiri lalu klik tombol merah untuk menjalankan uji verifikasi eksploitasi memori deterministik.
                        </p>
                    </div>
                </div>

                <!-- Vulnerable State (Alert Banner) -->
                <div id="demo-state-vulnerable" class="hidden space-y-4">
                    <div class="p-6 rounded-2xl bg-gradient-to-br from-rose-950/80 via-rose-900/40 to-black border-2 border-rose-500/80 shadow-2xl shadow-rose-950/50 space-y-4 relative overflow-hidden">
                        <div class="absolute -right-10 -bottom-10 w-40 h-40 bg-rose-500/20 rounded-full blur-2xl pointer-events-none"></div>

                        <div class="flex items-start space-x-3.5">
                            <div class="w-10 h-10 rounded-xl bg-rose-500/20 text-rose-400 flex items-center justify-center shrink-0 border border-rose-500/30">
                                <svg class="w-6 h-6 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                            </div>
                            <div class="space-y-1">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500 text-white uppercase tracking-wider">
                                    HASIL PENETRASI TERKONFIRMASI
                                </span>
                                <h3 id="demo-vuln-title" class="text-base sm:text-lg font-black text-rose-300">
                                    PENETRASI BERHASIL DILAKUKAN — SEGERA LAKUKAN PATCH!
                                </h3>
                                <p id="demo-vuln-subtitle" class="text-xs text-rose-100/90 leading-relaxed font-medium">
                                    Handler memori PHP target berhasil dipicu mengalami crash Zend Heap Exhaustion (CVE-2026-109618/19).
                                </p>
                            </div>
                        </div>

                        <!-- Action Callout Bar -->
                        <div class="p-3 bg-black/60 rounded-xl border border-rose-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                            <div class="text-xs text-rose-200">
                                <span class="font-bold text-white">Tindakan Rekomendasi:</span> Terapkan penonaktifan upload progress atau isolasi Nginx shield.
                            </div>
                            <button onclick="App.setTab('mitigation')" class="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white rounded-lg text-xs font-bold transition shadow whitespace-nowrap flex items-center space-x-1.5 self-start sm:self-auto">
                                <span>Buka Generator Remediasi</span>
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                            </button>
                        </div>
                    </div>

                    <!-- Technical Evidence Accordion -->
                    <div class="space-y-2">
                        <div class="flex items-center justify-between text-xs text-slate-300 font-bold px-1">
                            <span class="flex items-center space-x-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                                <span>Bukti Deterministik Crash Memori (Raw Evidence)</span>
                            </span>
                            <span id="demo-php-ver" class="text-[11px] font-mono text-cyan-300">PHP Version</span>
                        </div>
                        <pre id="demo-vuln-evidence" class="p-3.5 bg-black/80 rounded-xl border border-white/10 font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed select-all">Memuat bukti teknis...</pre>
                    </div>
                </div>

                <!-- Protected State -->
                <div id="demo-state-protected" class="hidden space-y-4">
                    <div class="p-6 rounded-2xl bg-gradient-to-br from-emerald-950/80 via-emerald-900/40 to-black border-2 border-emerald-500/80 shadow-2xl space-y-3">
                        <div class="flex items-start space-x-3.5">
                            <div class="w-10 h-10 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0 border border-emerald-500/30">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                            </div>
                            <div>
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500 text-black uppercase tracking-wider">
                                    SERVER TERLINDUNGI
                                </span>
                                <h3 class="text-base sm:text-lg font-black text-emerald-300 mt-1">
                                    PENETRASI DITOLAK — SERVER AMAN DARI PHP2SHELL
                                </h3>
                                <p id="demo-prot-subtitle" class="text-xs text-slate-300 mt-1 leading-relaxed">
                                    Payload multipart fuzzer tidak memicu memory crash pada request handler. Proteksi konfigurasi runtime aktif.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Unreachable State -->
                <div id="demo-state-unreachable" class="hidden space-y-4">
                    <div class="p-6 rounded-2xl bg-slate-900/90 border border-amber-500/40 shadow-xl space-y-3">
                        <div class="flex items-start space-x-3.5">
                            <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center shrink-0 border border-amber-500/20">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                            </div>
                            <div>
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 uppercase tracking-wider">
                                    HOST OFFLINE / GAGAL RESOLVE
                                </span>
                                <h3 id="demo-unreach-title" class="text-base font-bold text-white mt-1">
                                    Target Tidak Dapat Dihubungi
                                </h3>
                                <p id="demo-unreach-msg" class="text-xs text-slate-400 mt-1 leading-relaxed">
                                    Gerbang Network Pre-Flight menghentikan simulasi untuk menghindari kesimpulan keliru.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="assets/js/demo.js"></script>
