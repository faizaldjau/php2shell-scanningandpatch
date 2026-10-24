<!-- Tab 4: Standar OWASP & Hardening Matrix -->
<div id="tab-hardening" class="tab-content hidden space-y-6">
    <!-- Top Banner -->
    <div class="glass-panel p-6 rounded-2xl border border-white/10 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-16 -top-16 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div class="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
                <h2 class="text-xl font-bold text-white flex items-center space-x-2.5">
                    <span class="w-2.5 h-2.5 rounded-full bg-purple-400 radar-pulse"></span>
                    <span>Standar OWASP Top 10, Security-Hardening & Server-Hardening</span>
                </h2>
                <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                    Panduan baku pengamanan arsitektur aplikasi web dan infrastruktur server peradilan, mengintegrasikan standar <strong>OWASP Top 10 (2021)</strong>, metodologi <strong>WSTG v4.2</strong>, serta kerangka kerja <strong>Three-Tier Boundary Hardening</strong>.
                </p>
            </div>
            <div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                WSTG v4.2 Aligned
            </div>
        </div>
    </div>

    <!-- Three-Tier Boundary System Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
        <!-- Always Do -->
        <div class="glass-panel p-5 rounded-2xl border border-emerald-500/20 shadow-xl space-y-3.5 hover-lift">
            <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs uppercase tracking-wider pb-2 border-b border-white/5">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                <span>Always Do (Wajib Mutlak)</span>
            </div>
            <ul class="text-xs text-slate-300 space-y-2.5 leading-relaxed">
                <li class="flex items-start space-x-2">
                    <span class="text-emerald-400 mt-0.5">&check;</span>
                    <span><strong>Validasi di Boundary:</strong> Periksa panjang, skema, dan tipe data pada seluruh endpoint API.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-emerald-400 mt-0.5">&check;</span>
                    <span><strong>Parameterized Queries:</strong> Wajib gunakan PDO / Prepared Statements untuk seluruh query database.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-emerald-400 mt-0.5">&check;</span>
                    <span><strong>Secure Cookie Flags:</strong> Pasang flag <code class="text-emerald-400 font-mono text-[11px]">HttpOnly</code>, <code class="text-emerald-400 font-mono text-[11px]">Secure</code>, dan <code class="text-emerald-400 font-mono text-[11px]">SameSite=Lax</code>.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-emerald-400 mt-0.5">&check;</span>
                    <span><strong>Security Headers:</strong> Pasang HSTS, CSP, X-Frame-Options, dan X-Content-Type-Options: nosniff.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-emerald-400 mt-0.5">&check;</span>
                    <span><strong>Patch Biner Terjadwal:</strong> Mutakhirkan runtime interpreter PHP segera setelah CVE darurat dirilis.</span>
                </li>
            </ul>
        </div>

        <!-- Ask First -->
        <div class="glass-panel p-5 rounded-2xl border border-amber-500/20 shadow-xl space-y-3.5 hover-lift">
            <div class="flex items-center space-x-2 text-amber-400 font-bold text-xs uppercase tracking-wider pb-2 border-b border-white/5">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <span>Ask First (Review Tim Keamanan)</span>
            </div>
            <ul class="text-xs text-slate-300 space-y-2.5 leading-relaxed">
                <li class="flex items-start space-x-2">
                    <span class="text-amber-400 mt-0.5">&bull;</span>
                    <span><strong>Modul Unggahan Berkas:</strong> Handler upload putusan perkara SIPP wajib direview ekstensi & magic bytes-nya.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-amber-400 mt-0.5">&bull;</span>
                    <span><strong>Alur Autentikasi Baru:</strong> Penambahan integrasi SSO atau perubahan mekanisme login sesi.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-amber-400 mt-0.5">&bull;</span>
                    <span><strong>Kebijakan CORS:</strong> Jangan pernah mengaktifkan wildcard (<code class="text-amber-400 font-mono text-[11px]">*</code>) bersamaan dengan credentials.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-amber-400 mt-0.5">&bull;</span>
                    <span><strong>Permintaan Eksternal (SSRF):</strong> URL eksternal yang dipanggil server wajib divalidasi ke allowlist.</span>
                </li>
            </ul>
        </div>

        <!-- Never Do -->
        <div class="glass-panel p-5 rounded-2xl border border-rose-500/20 shadow-xl space-y-3.5 hover-lift">
            <div class="flex items-center space-x-2 text-rose-400 font-bold text-xs uppercase tracking-wider pb-2 border-b border-white/5">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path></svg>
                <span>Never Do (Pantangan Keras)</span>
            </div>
            <ul class="text-xs text-slate-300 space-y-2.5 leading-relaxed">
                <li class="flex items-start space-x-2">
                    <span class="text-rose-400 mt-0.5">&cross;</span>
                    <span><strong>Jangan Commit Rahasia:</strong> Dilarang keras menaruh password DB atau API key di repositori git.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-rose-400 mt-0.5">&cross;</span>
                    <span><strong>Jangan eval() / Dynamic Include:</strong> Hindari pemanggilan berkas langsung dari parameter <code class="text-rose-400 font-mono text-[11px]">include($_GET['p'])</code>.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-rose-400 mt-0.5">&cross;</span>
                    <span><strong>Jangan Percayai Ekstensi:</strong> Selalu cek magic bytes biner berkas PDF perkara SIPP saat diunggah.</span>
                </li>
                <li class="flex items-start space-x-2">
                    <span class="text-rose-400 mt-0.5">&cross;</span>
                    <span><strong>Jangan Bocorkan Stack Trace:</strong> Matikan <code class="text-rose-400 font-mono text-[11px]">display_errors</code> pada server produksi.</span>
                </li>
            </ul>
        </div>
    </div>

    <!-- Dasar Kebijakan Resmi Mahkamah Agung RI -->
    <div class="glass-panel rounded-2xl border border-amber-500/30 bg-gradient-to-r from-amber-950/40 via-black to-slate-950 p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/5">
            <div class="flex items-center space-x-2.5">
                <span class="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                <h3 class="text-sm font-bold text-white uppercase tracking-wider">
                    Dasar Kebijakan & Tim Teknis: Surat Ditjen Badilum MA-RI No. 135/DJU.3/TI1.1.1/X/2026
                </h3>
            </div>
            <a href="https://drive.google.com/open?id=1XKdEt3faVS8YPbSPaiaU_YsXTsg56Mul&usp=drive_copy" target="_blank" rel="noopener" class="text-xs font-semibold text-amber-400 hover:text-amber-300 underline flex items-center space-x-1">
                <span>▶ Video Panduan Update CentOS 7</span>
            </a>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div class="space-y-2 text-slate-300 leading-relaxed">
                <p><strong>Amanat Surat Resmi Badilum:</strong></p>
                <ul class="list-disc list-inside space-y-1 text-slate-400">
                    <li>Sebagian besar Server SIPP Pengadilan Negeri berjalan pada <strong>CentOS 7 & PHP 5.4/5.6 (Level Berbahaya)</strong>.</li>
                    <li>Satker wajib segera memperbarui PHP ke versi 5.6 yang telah diperbaiki (<code class="text-amber-300 font-mono">Custom Built MA RI: 2026-10-24</code>) via tautan <code class="text-cyan-300 font-mono">s.id/cvemari</code>.</li>
                    <li>Ambang batas versi aman PHP modern: <strong>PHP 8.5.12, 8.4.27, 8.3.36, atau 8.2.35</strong>.</li>
                    <li>Wajib restart seluruh runtime terkait (<code class="text-slate-300 font-mono">PHP-FPM, Apache mod_php, php-cgi</code>).</li>
                </ul>
            </div>

            <div class="p-3.5 bg-black/60 rounded-xl border border-white/5 space-y-2 text-[11px]">
                <div class="font-bold text-amber-400">Narahubung Teknis Badilum & BUA MA-RI:</div>
                <div class="space-y-1 text-slate-300">
                    <div>• <strong>sdr. Rian Andri Salam, S.Kom., M.MSI.</strong> (Kasubag Sistem Aplikasi): <span class="font-mono text-cyan-400">0815 9156 404</span></div>
                    <div>• <strong>sdr. Yunawan Kurnia, S.Kom., M.T.</strong> (Kasubag Bimbingan Teknis): <span class="font-mono text-cyan-400">0856 9716 311</span></div>
                    <div>• <strong>sdr. Ikhwanul Dawam Sutawijaya, S.Kom., M.H.</strong> (Kasubag Pengembangan TI): <span class="font-mono text-cyan-400">0811 1739 800</span></div>
                    <div>• <strong>sdr. Herru Semono, S.Kom</strong> (Prakom Ahli Muda Biro Hukum & Humas): <span class="font-mono text-cyan-400">0813 1771 0773</span></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Core Hardening Principles for SIPP Courts -->
    <div class="glass-panel rounded-2xl border border-white/10 shadow-2xl p-6 space-y-4">
        <h3 class="text-sm font-bold text-white flex items-center space-x-2">
            <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
            <span>Korelasi Kerentanan PHP2Shell terhadap Taksonomi Risiko OWASP Top 10</span>
        </h3>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div class="p-4 bg-black/40 rounded-xl border border-white/5 space-y-1">
                <div class="font-bold text-cyan-400">A06:2021 – Vulnerable and Outdated Components</div>
                <p class="text-slate-400 leading-relaxed">
                    Menjalankan PHP 5.6 pada CentOS 7 yang telah mencapai End-of-Life (EOL) tanpa pembaruan patch keamanan menempatkan server pada kategori risiko A06. Solusi permanen adalah migrasi biner ke PHP 8.x pada OS modern (Ubuntu 24.04 / AlmaLinux).
                </p>
            </div>
            <div class="p-4 bg-black/40 rounded-xl border border-white/5 space-y-1">
                <div class="font-bold text-amber-400">A05:2021 – Security Misconfiguration</div>
                <p class="text-slate-400 leading-relaxed">
                    Fitur bawaan <code class="text-slate-300 font-mono text-[11px]">session.upload_progress.enabled = On</code> aktif secara default sejak PHP 5.4, membuka celah polusi serializer worker dan OOM bailout. Menonaktifkannya di php.ini secara langsung menutup vektor serangan.
                </p>
            </div>
            <div class="p-4 bg-black/40 rounded-xl border border-white/5 space-y-1">
                <div class="font-bold text-rose-400">A03:2021 – Injection & Command Execution</div>
                <p class="text-slate-400 leading-relaxed">
                    Eksploitasi PHP2Shell memanipulasi pointer eksekusi internal Zend Engine (<code class="text-slate-300 font-mono text-[11px]">zif_system</code>) atau merangkai injeksi sesi dengan celah LFI aplikasi web (Chain A), berujung pada eksekusi perintah shell acak (*Remote Code Execution*).
                </p>
            </div>
            <div class="p-4 bg-black/40 rounded-xl border border-white/5 space-y-1">
                <div class="font-bold text-purple-400">A01:2021 – Broken Access Control</div>
                <p class="text-slate-400 leading-relaxed">
                    Kerentanan ini bersifat *pre-authentication* (terjadi sebelum session divalidasi dan sebelum skrip aplikasi dieksekusi). Oleh karena itu, pengamanan autentikasi aplikasi biasa tidak mampu menahan serangan ini tanpa adanya WAF atau pengerasan runtime.
                </p>
            </div>
        </div>
    </div>

    <!-- WSTG Checklist Table -->
    <div class="glass-panel rounded-2xl border border-white/10 shadow-2xl overflow-hidden">
        <div class="px-6 py-4 border-b border-white/5">
            <h4 class="text-xs font-bold text-white uppercase tracking-wider">
                Matriks Uji Keamanan Berbasis OWASP Web Security Testing Guide (WSTG v4.2)
            </h4>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs border-collapse">
                <thead>
                    <tr class="bg-slate-950/70 border-b border-white/5 text-slate-400 font-semibold uppercase text-[10px]">
                        <th class="px-5 py-3">ID Kontrol</th>
                        <th class="px-5 py-3">Nama Pengujian</th>
                        <th class="px-5 py-3">Cakupan Pemeriksaan</th>
                        <th class="px-5 py-3">Tindakan Remediasi</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-white/5 text-slate-300">
                    <tr class="hover:bg-slate-800/20 transition">
                        <td class="px-5 py-3 font-mono text-cyan-400 font-bold">WSTG-INFO-02</td>
                        <td class="px-5 py-3 font-semibold text-white">Fingerprint Web Server</td>
                        <td class="px-5 py-3 text-slate-400">Pemeriksaan header X-Powered-By dan Server banner</td>
                        <td class="px-5 py-3 text-slate-300 font-mono text-[11px]">expose_php = Off, ServerTokens Prod</td>
                    </tr>
                    <tr class="hover:bg-slate-800/20 transition">
                        <td class="px-5 py-3 font-mono text-cyan-400 font-bold">WSTG-CONF-04</td>
                        <td class="px-5 py-3 font-semibold text-white">Exposed Sensitive Files</td>
                        <td class="px-5 py-3 text-slate-400">Pencarian berkas .git, .env, backup database, phpinfo</td>
                        <td class="px-5 py-3 text-slate-300 font-mono text-[11px]">Hapus file dari web root, Nginx deny all</td>
                    </tr>
                    <tr class="hover:bg-slate-800/20 transition">
                        <td class="px-5 py-3 font-mono text-cyan-400 font-bold">WSTG-CONF-06</td>
                        <td class="px-5 py-3 font-semibold text-white">HTTP Methods Testing</td>
                        <td class="px-5 py-3 text-slate-400">Pemeriksaan metode TRACE (Cross-Site Tracing) & OPTIONS</td>
                        <td class="px-5 py-3 text-slate-300 font-mono text-[11px]">TraceEnable Off (Apache)</td>
                    </tr>
                    <tr class="hover:bg-slate-800/20 transition">
                        <td class="px-5 py-3 font-mono text-cyan-400 font-bold">WSTG-SESS-02</td>
                        <td class="px-5 py-3 font-semibold text-white">Cookie Security Flags</td>
                        <td class="px-5 py-3 text-slate-400">Verifikasi flag HttpOnly, Secure, SameSite pada PHPSESSID</td>
                        <td class="px-5 py-3 text-slate-300 font-mono text-[11px]">session.cookie_* di php.ini</td>
                    </tr>
                    <tr class="hover:bg-slate-800/20 transition">
                        <td class="px-5 py-3 font-mono text-cyan-400 font-bold">WSTG-VULN-01</td>
                        <td class="px-5 py-3 font-semibold text-white">Runtime Vulnerability Audit</td>
                        <td class="px-5 py-3 text-slate-400">Audit kerentanan PHP2Shell (CVE-2026-109618/19)</td>
                        <td class="px-5 py-3 text-slate-300 font-mono text-[11px]">Pembaruan biner atau isolasi WAF & matikan upload progress</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
