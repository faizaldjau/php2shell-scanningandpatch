<!-- Tab 3: Interactive Technical Guidance & Config Generator -->
<div id="tab-mitigation" class="tab-content hidden space-y-6">
    <!-- Top Banner -->
    <div class="glass-panel p-6 rounded-2xl border border-white/10 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-16 -top-16 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div class="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
                <h2 class="text-xl font-bold text-white flex items-center space-x-2.5">
                    <span class="w-2.5 h-2.5 rounded-full bg-cyan-400 radar-pulse"></span>
                    <span>Studio Generator Konfigurasi & Engine Deteksi WAF/IDS</span>
                </h2>
                <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                    Hasilkan template konfigurasi keamanan siap pasang dan gunakan aturan deteksi otentik dari <strong>repositori peneliti keamanan (ikow/php2shell-poc)</strong> serta <strong>OWASP ModSecurity Core Rule Set (CRS)</strong> untuk memproteksi server SIPP Pengadilan.
                </p>
            </div>
            <div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Integrated Cloned Engines
            </div>
        </div>
    </div>

    <!-- Generator Studio Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Configuration Selector Sidebar (4 cols) -->
        <div class="lg:col-span-4 glass-panel p-5 rounded-2xl border border-white/10 shadow-xl space-y-4 max-h-[750px] overflow-y-auto">
            <!-- Group 1: Server Configs -->
            <div>
                <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider px-2 mb-2">
                    Template Pengerasan Server
                </h3>

                <div class="space-y-1.5">
                    <button onclick="Mitigation.loadSnippet('phpini', this)" class="cfg-btn active w-full text-left px-3.5 py-2.5 rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 font-semibold text-xs flex items-center justify-between transition group hover-lift">
                        <div class="flex items-center space-x-2.5">
                            <div class="w-7 h-7 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-mono text-xs">INI</div>
                            <div>
                                <div class="font-semibold">php.ini Hardening Standard</div>
                                <div class="text-[10px] text-slate-400 font-normal">Matikan upload_progress & batasi nesting</div>
                            </div>
                        </div>
                        <svg class="w-4 h-4 text-cyan-400 opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                    </button>

                    <button onclick="Mitigation.loadSnippet('nginx', this)" class="cfg-btn w-full text-left px-3.5 py-2.5 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition group hover-lift">
                        <div class="flex items-center space-x-2.5">
                            <div class="w-7 h-7 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-mono text-xs">NGX</div>
                            <div>
                                <div class="font-semibold">Nginx Shield Standalone</div>
                                <div class="text-[10px] text-slate-400 font-normal">Buffer size limits & filter request</div>
                            </div>
                        </div>
                        <svg class="w-4 h-4 text-slate-500 opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                    </button>

                    <button onclick="Mitigation.loadSnippet('reverse_proxy', this)" class="cfg-btn w-full text-left px-3.5 py-2.5 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition group hover-lift">
                        <div class="flex items-center space-x-2.5">
                            <div class="w-7 h-7 rounded-lg bg-purple-500/20 text-purple-400 flex items-center justify-center font-mono text-xs">PRX</div>
                            <div>
                                <div class="font-semibold">Nginx Reverse Proxy (SIPP)</div>
                                <div class="text-[10px] text-slate-400 font-normal">Perisai Frontend untuk CentOS 7 Backend</div>
                            </div>
                        </div>
                        <svg class="w-4 h-4 text-slate-500 opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                    </button>

                    <button onclick="Mitigation.loadSnippet('modsecurity', this)" class="cfg-btn w-full text-left px-3.5 py-2.5 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition group hover-lift">
                        <div class="flex items-center space-x-2.5">
                            <div class="w-7 h-7 rounded-lg bg-orange-500/20 text-orange-400 flex items-center justify-center font-mono text-xs">SEC</div>
                            <div>
                                <div class="font-semibold">Apache ModSecurity Custom</div>
                                <div class="text-[10px] text-slate-400 font-normal">Rule 2026101 (Penolak Upload Progress)</div>
                            </div>
                        </div>
                        <svg class="w-4 h-4 text-slate-500 opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                    </button>
                </div>
            </div>

            <!-- Group 2: Cloned Authentic Detection Rules -->
            <div class="pt-3 border-t border-white/5">
                <h4 class="text-[11px] font-bold text-cyan-400 uppercase tracking-wider px-2 mb-2 flex items-center space-x-1.5">
                    <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                    <span>Engine Peneliti & OWASP CRS (Cloned)</span>
                </h4>

                <div class="space-y-1.5">
                    <button onclick="Mitigation.loadSnippet('p2s_modsecurity', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <div>
                            <div class="font-medium">ModSecurity v2/v3 Rules</div>
                            <div class="text-[10px] text-slate-500">engines/p2s-poc-toolkit/detection/modsecurity.conf</div>
                        </div>
                        <span class="text-[10px] font-mono text-rose-400">WAF</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('p2s_suricata', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <div>
                            <div class="font-medium">Suricata / Snort IDS Rules</div>
                            <div class="text-[10px] text-slate-500">engines/p2s-poc-toolkit/detection/php2shell.rules</div>
                        </div>
                        <span class="text-[10px] font-mono text-amber-400">IDS</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('p2s_sigma', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <div>
                            <div class="font-medium">Sigma SIEM Detection Rule</div>
                            <div class="text-[10px] text-slate-500">engines/p2s-poc-toolkit/detection/php2shell.yaml</div>
                        </div>
                        <span class="text-[10px] font-mono text-blue-400">SIEM</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('p2s_lua', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <div>
                            <div class="font-medium">HAProxy Lua WAF Script</div>
                            <div class="text-[10px] text-slate-500">engines/p2s-poc-toolkit/detection/php2shell.lua</div>
                        </div>
                        <span class="text-[10px] font-mono text-purple-400">LUA</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('owasp_crs_php', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <div>
                            <div class="font-medium">OWASP CRS PHP Protection</div>
                            <div class="text-[10px] text-slate-500">engines/owasp-modsecurity-crs/.../PHP.conf</div>
                        </div>
                        <span class="text-[10px] font-mono text-emerald-400">CRS</span>
                    </button>
                </div>
            </div>

            <!-- Group 3: Bash Automation -->
            <div class="pt-3 border-t border-white/5">
                <h4 class="text-[11px] font-bold text-slate-400 uppercase tracking-wider px-2 mb-2">Skrip Otomasi Bash Shell</h4>

                <div class="space-y-1.5">
                    <button onclick="Mitigation.loadSnippet('bash_mari_centos7', this)" class="cfg-btn w-full text-left px-3.5 py-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-300 hover:text-white hover:bg-amber-500/20 text-xs flex items-center justify-between transition group">
                        <div>
                            <div class="font-bold flex items-center space-x-1.5">
                                <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                                <span>Patch Resmi MA-RI (CentOS 7 SIPP)</span>
                            </div>
                            <div class="text-[10px] text-amber-200/70">Surat Badilum 135/DJU.3/TI1.1.1/X/2026</div>
                        </div>
                        <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-bold">s.id/cvemari</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('bash_ubuntu', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <span class="font-medium text-xs">Otomasi Ubuntu 24.04 / 22.04 LTS</span>
                        <span class="text-[10px] font-mono text-emerald-400">APT</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('bash_centos7', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <span class="font-medium text-xs">Otomasi Penguncian php.ini CentOS 7</span>
                        <span class="text-[10px] font-mono text-amber-400">Lock Only</span>
                    </button>

                    <button onclick="Mitigation.loadSnippet('bash_almalinux', this)" class="cfg-btn w-full text-left px-3.5 py-2 rounded-xl border border-white/5 bg-slate-900/60 text-slate-300 hover:text-white hover:bg-slate-800 text-xs flex items-center justify-between transition">
                        <span class="font-medium text-xs">Otomasi AlmaLinux / Rocky (8/9)</span>
                        <span class="text-[10px] font-mono text-cyan-400">DNF / Remi</span>
                    </button>
                </div>
            </div>
        </div>

        <!-- Code Studio Viewer (8 cols) -->
        <div class="lg:col-span-8 glass-panel rounded-2xl border border-white/10 shadow-2xl flex flex-col overflow-hidden">
            <!-- Studio Header Bar -->
            <div class="bg-[#0c1220] px-5 py-4 border-b border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div class="flex items-center space-x-3">
                    <div class="flex items-center space-x-1.5">
                        <span class="terminal-dot dot-red"></span>
                        <span class="terminal-dot dot-yellow"></span>
                        <span class="terminal-dot dot-green"></span>
                    </div>
                    <div>
                        <h4 id="snippet-title" class="text-xs font-bold text-white font-mono">php.ini</h4>
                        <p id="snippet-desc" class="text-[11px] text-slate-400">Konfigurasi hardening direktif runtime PHP.</p>
                    </div>
                </div>

                <div class="flex items-center space-x-2">
                    <a href="https://drive.google.com/open?id=1XKdEt3faVS8YPbSPaiaU_YsXTsg56Mul&usp=drive_copy" target="_blank" rel="noopener" class="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <span>Video Panduan MA</span>
                    </a>
                    <button id="btn-copy-snippet" onclick="Mitigation.copyCurrent()" class="px-3.5 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                        <span>Salin File</span>
                    </button>
                    <button id="btn-download-snippet" onclick="Mitigation.downloadCurrent()" class="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-white/10 rounded-lg text-xs font-medium flex items-center space-x-1.5 transition">
                        <svg class="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                        <span>Unduh File</span>
                    </button>
                </div>
            </div>

            <!-- Code Content Area -->
            <div class="relative bg-[#050811] p-5 flex-grow overflow-x-auto max-h-[660px]">
                <pre id="snippet-code" class="text-xs text-slate-300 font-mono whitespace-pre leading-relaxed selection:bg-cyan-500/30">Memuat konfigurasi...</pre>
            </div>
        </div>
    </div>
</div>

<script>
window.Mitigation = {
    currentType: 'phpini',
    currentContent: '',

    init() {
        this.loadSnippet('phpini');
    },

    async loadSnippet(type, btnElement = null) {
        this.currentType = type;

        if (btnElement) {
            document.querySelectorAll('.cfg-btn').forEach(b => {
                b.classList.remove('active', 'border-cyan-500/30', 'bg-cyan-500/10', 'text-cyan-300', 'font-semibold');
                b.classList.add('border-white/5', 'bg-slate-900/60', 'text-slate-300');
            });
            btnElement.classList.add('active', 'border-cyan-500/30', 'bg-cyan-500/10', 'text-cyan-300', 'font-semibold');
            btnElement.classList.remove('border-white/5', 'bg-slate-900/60', 'text-slate-300');
        }

        try {
            const resp = await fetch(`api.php?action=get_config&type=${type}`);
            const res = await resp.json();

            if (res.success && res.content) {
                this.currentContent = res.content;
                const codeEl = document.getElementById('snippet-code');
                const titleEl = document.getElementById('snippet-title');
                const descEl = document.getElementById('snippet-desc');

                if (codeEl) codeEl.innerText = res.content;

                const titles = {
                    phpini: 'php.ini — Security Hardening Directives',
                    nginx: 'nginx.conf — Shield & Buffer Restrictions',
                    reverse_proxy: 'nginx-reverse-proxy.conf — SIPP Frontend Shield',
                    modsecurity: 'mod_security.conf — Custom CRS Rules 2026101/102',
                    p2s_modsecurity: 'modsecurity.conf — ikow/php2shell-poc Researcher Rules',
                    p2s_suricata: 'php2shell.rules — Suricata / Snort IDS Signature',
                    p2s_sigma: 'php2shell.yaml — Sigma SIEM Detection Rule',
                    p2s_lua: 'php2shell.lua — HAProxy Lua Protection Filter',
                    owasp_crs_php: 'REQUEST-933-APPLICATION-ATTACK-PHP.conf — OWASP CRS Official',
                    bash_mari_centos7: 'patch_mari_centos7.sh — Resmi Mahkamah Agung RI (s.id/cvemari)',
                    bash_ubuntu: 'remediation_ubuntu.sh — APT Upgrade & php.ini Lock',
                    bash_centos7: 'remediation_centos7_sipp.sh — Legacy CentOS 7 Hardening',
                    bash_almalinux: 'remediation_almalinux.sh — DNF / Remi Upgrade & Lock'
                };

                const descs = {
                    phpini: 'Menonaktifkan pelacakan upload progress, membatasi array nesting probe, dan menyembunyikan versi teknologi.',
                    nginx: 'Membatasi ukuran buffer, memasang security headers, dan memblokir request PHP_SESSION_UPLOAD_PROGRESS.',
                    reverse_proxy: 'Pola perisai Nginx di lini depan untuk menyaring request kotor sebelum diteruskan ke Apache CentOS 7 backend.',
                    modsecurity: 'Aturan deteksi WAF ModSecurity untuk memblokir parameter eksploitasi dan nested array keys ekstrem.',
                    p2s_modsecurity: 'Aturan resmi ModSecurity v2/v3 dari repo ikow/php2shell-poc untuk memblokir Rule 9900100 & 9900102.',
                    p2s_suricata: 'Signature IDS Suricata/Snort untuk mendeteksi transmisi exploit PHP2Shell di tingkat lalu-lintas jaringan.',
                    p2s_sigma: 'Aturan deteksi SIEM format Sigma untuk monitoring log web server terpusat di lingkungan instansi.',
                    p2s_lua: 'Skrip Lua non-blocking untuk load balancer HAProxy untuk drop request multipart malicious.',
                    owasp_crs_php: 'Kompilasi aturan proteksi aplikasi PHP dari OWASP ModSecurity Core Rule Set resmi.',
                    bash_mari_centos7: 'Skrip resmi Mahkamah Agung RI untuk memasang paket biner kustom php-5.6-mari-centos7-20261024.tar.gz pada CentOS 7 SIPP.',
                    bash_ubuntu: 'Menjalankan apt upgrade paket Canonical dan mengunci konfigurasi php.ini secara otomatis.',
                    bash_centos7: 'Skrip hardening tanpa patch biner untuk mengunci php.ini dan me-restart service SIPP di CentOS 7.',
                    bash_almalinux: 'Mengupgrade paket Remi/Sistem dan mengunci seluruh file konfigurasi php.ini pada Alma/Rocky Linux.'
                };

                if (titleEl) titleEl.innerText = titles[type] || 'Konfigurasi Keamanan';
                if (descEl) descEl.innerText = descs[type] || '';
            }
        } catch (err) {
            console.error('[Load Snippet Error]', err);
        }
    },

    copyCurrent() {
        if (!this.currentContent) return;
        const btn = document.getElementById('btn-copy-snippet');
        App.copyText(this.currentContent, btn);
    },

    downloadCurrent() {
        if (!this.currentContent) return;
        let ext = '.conf';
        if (this.currentType.startsWith('bash_')) ext = '.sh';
        else if (this.currentType === 'phpini') ext = '.ini';
        else if (this.currentType === 'p2s_suricata') ext = '.rules';
        else if (this.currentType === 'p2s_sigma') ext = '.yaml';
        else if (this.currentType === 'p2s_lua') ext = '.lua';

        const filename = `${this.currentType}${ext}`;
        const blob = new Blob([this.currentContent], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        App.showToast(`Berkas ${filename} berhasil diunduh.`, 'success');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    window.Mitigation.init();
});
</script>
