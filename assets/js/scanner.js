/**
 * Remote Blackbox Scanner Controller (Modern UI & Cloned Engine Edition)
 */

window.Scanner = {
    isScanning: false,
    activeScanId: null,
    pollTimer: null,
    results: [],
    mode: 'single', // 'single' or 'bulk'

    init() {
        this.bindEvents();
    },

    bindEvents() {
        const form = document.getElementById('scan-form');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startScan();
            });
        }
    },

    switchInputMode(mode) {
        this.mode = mode;
        const singleContainer = document.getElementById('input-container-single');
        const bulkContainer = document.getElementById('input-container-bulk');
        const btnSingle = document.getElementById('mode-btn-single');
        const btnBulk = document.getElementById('mode-btn-bulk');

        if (mode === 'single') {
            if (singleContainer) singleContainer.classList.remove('hidden');
            if (bulkContainer) bulkContainer.classList.add('hidden');

            if (btnSingle) {
                btnSingle.className = "px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition shadow-sm flex items-center space-x-1.5";
            }
            if (btnBulk) {
                btnBulk.className = "px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition flex items-center space-x-1.5";
            }
        } else {
            if (singleContainer) singleContainer.classList.add('hidden');
            if (bulkContainer) bulkContainer.classList.remove('hidden');

            if (btnSingle) {
                btnSingle.className = "px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition flex items-center space-x-1.5";
            }
            if (btnBulk) {
                btnBulk.className = "px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition shadow-sm flex items-center space-x-1.5";
            }
        }
    },

    handleFileSelected(input) {
        const label = document.getElementById('file-selected-name');
        if (input && input.files && input.files[0]) {
            const file = input.files[0];
            if (label) {
                label.innerHTML = `<span class="text-emerald-400 font-mono font-bold">${App.escapeHtml(file.name)}</span> (${(file.size / 1024).toFixed(1)} KB siap dipindai)`;
            }
        }
    },

    async startScan() {
        if (this.isScanning) return;

        const form = document.getElementById('scan-form');
        const formData = new FormData(form);
        const singleUrl = formData.get('target_url');
        const fileInput = document.getElementById('target_file');

        if (this.mode === 'single' && !singleUrl) {
            App.showToast('Harap masukkan target domain/URL sasaran!', 'warning');
            return;
        }

        if (this.mode === 'bulk' && (!fileInput || !fileInput.files.length)) {
            App.showToast('Harap pilih berkas teks (.txt) yang memuat daftar sasaran!', 'warning');
            return;
        }

        this.isScanning = true;
        this.updateScanUI(true);
        this.results = [];
        this.renderResultsTable();

        try {
            const resp = await fetch('api.php?action=start_scan', {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();

            if (!data.success) {
                App.showToast(data.error || 'Gagal memulai pemindaian', 'error');
                this.isScanning = false;
                this.updateScanUI(false);
                return;
            }

            if (data.is_bulk) {
                this.activeScanId = data.scan_id;
                App.showToast(`Memulai audit massal terhadap ${data.total_hosts} sasaran...`, 'info');
                this.startPolling(data.scan_id);
            } else {
                this.results = [data];
                this.renderResultsTable();
                this.isScanning = false;
                this.updateScanUI(false);
                if (data.is_reachable === false) {
                    App.showToast('Target tidak dapat dijangkau (DNS/Koneksi Gagal).', 'warning');
                } else {
                    App.showToast('Audit selesai! Hasil engine berhasil diproses.', 'success');
                }
            }
        } catch (err) {
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.isScanning = false;
            this.updateScanUI(false);
        }
    },

    startPolling(scanId) {
        if (this.pollTimer) clearInterval(this.pollTimer);

        this.pollTimer = setInterval(async () => {
            try {
                const resp = await fetch(`api.php?action=scan_status&scan_id=${encodeURIComponent(scanId)}`);
                const res = await resp.json();

                if (!res.success || !res.data) {
                    clearInterval(this.pollTimer);
                    this.isScanning = false;
                    this.updateScanUI(false);
                    return;
                }

                const task = res.data;
                this.updateProgressBar(task.progress, task.current_host, task.processed_hosts, task.total_hosts);
                this.results = task.results || [];
                this.renderResultsTable();

                if (task.status === 'completed' || task.status === 'error') {
                    clearInterval(this.pollTimer);
                    this.isScanning = false;
                    this.updateScanUI(false);
                    App.showToast(`Audit massal selesai (${task.processed_hosts}/${task.total_hosts} target).`, 'success');
                }
            } catch (err) {
                console.error('[Polling Error]', err);
            }
        }, 1200);
    },

    updateScanUI(scanning) {
        const btn = document.getElementById('btn-submit-scan');
        const progressBox = document.getElementById('scan-progress-box');
        if (btn) {
            btn.disabled = scanning;
            btn.innerHTML = scanning ? `
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> <span>Sedang Memindai...</span>
            ` : `
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> <span>Mulai Audit Keamanan</span>
            `;
        }
        if (progressBox) {
            progressBox.classList.toggle('hidden', !scanning);
        }
    },

    updateProgressBar(pct, currentHost, processed, total) {
        const bar = document.getElementById('scan-progress-bar');
        const text = document.getElementById('scan-progress-text');
        const hostEl = document.getElementById('scan-current-host');

        if (bar) bar.style.width = `${pct}%`;
        if (text) text.innerText = `${pct}% (${processed}/${total} sasaran)`;
        if (hostEl && currentHost) hostEl.innerText = `Sedang menguji sasaran: ${currentHost}`;
    },

    renderResultsTable() {
        const tbody = document.getElementById('results-tbody');
        const countBox = document.getElementById('results-count');
        const emptyState = document.getElementById('results-empty');
        const tableContainer = document.getElementById('results-table-container');

        if (!tbody) return;

        if (!this.results.length) {
            if (emptyState) emptyState.classList.remove('hidden');
            if (tableContainer) tableContainer.classList.add('hidden');
            if (countBox) countBox.innerText = '0 Sasaran';
            return;
        }

        if (emptyState) emptyState.classList.add('hidden');
        if (tableContainer) tableContainer.classList.remove('hidden');
        if (countBox) countBox.innerText = `${this.results.length} Sasaran`;

        tbody.innerHTML = this.results.map((item, idx) => {
            const isReachable = item.is_reachable !== false && item.overall_risk !== 'UNREACHABLE';
            const p2s = item.php2shell || {};
            const owasp = item.owasp || {};

            let p2sBadge;
            let owaspBadge;
            let riskBadge;

            if (!isReachable) {
                // Pre-flight reachability failure: NO FALSE "SAFE" OR "0/100" VERDICTS!
                p2sBadge = `<span class="inline-flex items-center px-2.5 py-1 bg-slate-800 text-slate-400 border border-slate-700 rounded-lg text-xs font-mono font-medium">
                    <span class="w-1.5 h-1.5 rounded-full bg-slate-500 mr-1.5"></span> HOST OFFLINE
                </span>`;
                owaspBadge = `<div class="flex items-center space-x-1.5 text-slate-500 text-xs font-mono">
                    <span>N/A (Unreachable)</span>
                </div>`;
                riskBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">UNREACHABLE</span>`;
            } else {
                const isVuln = (p2s.vulnerable === true);
                const isPotentiallyVuln = (p2s.status === 'POTENTIALLY_VULNERABLE');
                const isSafe = (p2s.vulnerable === false && !isPotentiallyVuln);

                if (isVuln) {
                    p2sBadge = `<span class="inline-flex items-center px-2.5 py-1 bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded-lg text-xs font-mono font-bold glow-rose">
                        <span class="w-1.5 h-1.5 rounded-full bg-rose-500 mr-1.5 animate-pulse"></span> VULNERABLE
                    </span>`;
                } else if (isPotentiallyVuln) {
                    p2sBadge = `<span class="inline-flex items-center px-2.5 py-1 bg-amber-500/10 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-mono font-bold glow-amber">
                        <span class="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5"></span> POTENTIAL VULN
                    </span>`;
                } else if (isSafe) {
                    p2sBadge = `<span class="inline-flex items-center px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-mono font-semibold">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span> PATCHED / SAFE
                    </span>`;
                } else {
                    p2sBadge = `<span class="inline-flex items-center px-2.5 py-1 bg-slate-800 text-slate-400 border border-white/5 rounded-lg text-xs font-mono">
                        INCONCLUSIVE
                    </span>`;
                }

                const owaspScore = (owasp.score !== null && owasp.score !== undefined) ? owasp.score : 0;
                const owaspGrade = owasp.grade || 'N/A';
                const gradeColor = owaspScore >= 80 ? 'text-emerald-400' : (owaspScore >= 60 ? 'text-amber-400' : 'text-rose-400');

                owaspBadge = `<div class="flex items-center space-x-1.5">
                    <span class="font-bold text-sm ${gradeColor}">${owaspScore}/100</span>
                    <span class="text-xs text-slate-400">(${owaspGrade})</span>
                </div>`;

                const riskLevel = item.overall_risk || (isVuln ? 'CRITICAL' : 'LOW');
                riskBadge = riskLevel === 'CRITICAL' ?
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">CRITICAL</span>` :
                    (riskLevel === 'HIGH' ?
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-800">HIGH</span>` :
                    (riskLevel === 'MEDIUM' ?
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">MEDIUM</span>` :
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-white/5">LOW / MODERATE</span>`));
            }

            return `
                <tr class="hover:bg-slate-800/30 transition">
                    <td class="px-5 py-4 font-mono text-xs text-cyan-300 font-semibold">${App.escapeHtml(item.target)}</td>
                    <td class="px-5 py-4">${p2sBadge}</td>
                    <td class="px-5 py-4">${owaspBadge}</td>
                    <td class="px-5 py-4">${riskBadge}</td>
                    <td class="px-5 py-4 text-right">
                        <button onclick="Scanner.showDetailModal(${idx})" class="px-3 py-1.5 text-xs bg-slate-800 hover:bg-cyan-950/60 text-cyan-300 hover:text-cyan-200 border border-white/10 hover:border-cyan-500/30 rounded-lg transition font-medium">
                            ${isReachable ? 'Rincian & Bukti' : 'Diagnosa Koneksi'}
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    },

    showDetailModal(index) {
        const item = this.results[index];
        if (!item) return;

        const modal = document.getElementById('detail-modal');
        const modalContent = document.getElementById('modal-content');
        if (!modal || !modalContent) return;

        const isReachable = item.is_reachable !== false && item.overall_risk !== 'UNREACHABLE';
        const p2s = item.php2shell || {};
        const owasp = item.owasp || {};
        const adv = p2s.sipp_badilum_advisory;
        const distroAdv = p2s.distro_advisory;

        let advisoryHtml = '';
        if (adv) {
            advisoryHtml = `
                <div class="p-4 rounded-xl border ${adv.is_mari_patched ? 'border-emerald-500/50 bg-emerald-950/40 text-emerald-200' : 'border-amber-500/50 bg-amber-950/40 text-amber-200'} space-y-2">
                    <div class="flex items-center justify-between font-bold text-xs">
                        <span class="flex items-center space-x-1.5">
                            <span class="w-2 h-2 rounded-full ${adv.is_mari_patched ? 'bg-emerald-400' : 'bg-amber-400'}"></span>
                            <span>Instruksi Surat Ditjen Badilum MA-RI No. ${App.escapeHtml(adv.surat_no)}</span>
                        </span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${adv.is_mari_patched ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'}">
                            ${App.escapeHtml(adv.status_label)}
                        </span>
                    </div>
                    <p class="text-xs leading-relaxed text-slate-300">
                        ${adv.is_mari_patched ? 'Server SIPP ini telah terpasang patch biner kustom resmi Mahkamah Agung.' : 'Server terindikasi CentOS 7 SIPP (PHP 5.4/5.6 EOL) dan belum memasang patch resmi MA-RI. Gunakan perintah one-liner resmi di bawah:'}
                    </p>
                    ${!adv.is_mari_patched ? `
                        <div class="p-2 bg-black rounded font-mono text-[10px] text-amber-300 select-all border border-white/10 break-all">
                            ${App.escapeHtml(adv.one_liner)}
                        </div>
                    ` : ''}
                </div>
            `;
        } else if (distroAdv) {
            advisoryHtml = `
                <div class="p-4 rounded-xl border border-blue-500/40 bg-blue-950/30 text-blue-200 space-y-2">
                    <div class="flex items-center justify-between font-bold text-xs">
                        <span class="flex items-center space-x-1.5">
                            <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
                            <span>Target Sistem Operasi: ${App.escapeHtml(distroAdv.distro)}</span>
                        </span>
                    </div>
                    <p class="text-xs leading-relaxed text-slate-300">
                        ${App.escapeHtml(distroAdv.message)}
                    </p>
                </div>
            `;
        }

        if (!isReachable) {
            // UNREACHABLE / DNS RESOLUTION FAILURE MODAL VIEW
            const unreach = item.unreachable_details || {};
            modalContent.innerHTML = `
                <div class="space-y-4">
                    <div class="p-4 bg-slate-900/60 rounded-xl border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                            <h4 class="text-sm font-bold text-cyan-300 font-mono">${App.escapeHtml(item.target)}</h4>
                            <p class="text-xs text-slate-500">Waktu Diagnosa: ${item.scanned_at || 'Selesai'}</p>
                        </div>
                        <div class="flex items-center space-x-2">
                            <span class="text-xs font-mono font-bold px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 border border-slate-700">
                                Status: Host Offline / Unreachable
                            </span>
                        </div>
                    </div>

                    <!-- Warning Callout -->
                    <div class="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl space-y-2">
                        <div class="flex items-center space-x-2 text-amber-400 font-bold text-sm">
                            <svg class="w-5 h-5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                            <span>${App.escapeHtml(unreach.title || 'DNS Resolution Failed / Target Offline')}</span>
                        </div>
                        <p class="text-xs text-slate-300 leading-relaxed">${App.escapeHtml(unreach.message || p2s.reason || 'Koneksi ke host sasaran gagal.')}</p>
                    </div>

                    <!-- Technical Explanation & Resolution Steps -->
                    <div class="p-4 bg-black/60 border border-white/5 rounded-xl space-y-3">
                        <h5 class="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center space-x-2">
                            <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                            <span>Panduan Akses Intranet Pengadilan (SIPP Lokal)</span>
                        </h5>
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Engine Network Pre-Flight menghentikan audit sebelum probe exploit dijalankan guna mencegah kesimpulan keliru (false safe report). Domain intranet seperti <code class="text-cyan-300 font-mono">sipplokal.pn-*.go.id</code> hanya dapat diakses dari dalam jaringan instansi.
                        </p>
                        <div class="text-[11px] text-slate-300 bg-slate-950 p-3 rounded-lg border border-white/5 space-y-1.5">
                            <div class="font-semibold text-white">Langkah untuk Mengaudit Target Ini:</div>
                            <ol class="list-decimal list-inside space-y-1 text-slate-400">
                                <li>Pastikan komputer Anda terhubung ke <strong>VPN Mahkamah Agung / Jaringan LAN Pengadilan</strong> yang memiliki rute ke server tersebut.</li>
                                <li>Jika DNS lokal tidak tersedia di jaringan pengujian, petakan IP server secara manual pada berkas hosts Windows:
                                    <div class="my-1.5 p-2 bg-black font-mono text-[10px] text-emerald-400 rounded border border-white/10 select-all">
                                        # Buka Notepad as Administrator: C:\\Windows\\System32\\drivers\\etc\\hosts<br>
                                        192.168.1.xxx  sipplokal.pn-tilamuta.go.id
                                    </div>
                                </li>
                                <li>Setelah koneksi aktif, ulangi proses audit melalui tools ini.</li>
                            </ol>
                        </div>
                    </div>
                </div>
            `;
            modal.classList.remove('hidden');
            return;
        }

        // REACHABLE TARGET MODAL VIEW
        let findingsHtml = (owasp.findings || []).map(f => `
            <div class="p-3.5 bg-black/40 border border-white/5 rounded-xl text-xs space-y-1.5">
                <div class="flex items-center justify-between">
                    <span class="font-bold text-white">${App.escapeHtml(f.title)}</span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${f.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : (f.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' : 'bg-amber-950 text-amber-300 border border-amber-800')}">${f.severity}</span>
                </div>
                <p class="text-slate-400 leading-relaxed">${App.escapeHtml(f.desc)}</p>
                <div class="text-cyan-300 font-mono text-[11px] bg-slate-950 p-2 rounded-lg border border-white/5">${App.escapeHtml(f.remediation)}</div>
            </div>
        `).join('');

        if (!findingsHtml) {
            findingsHtml = `<p class="text-xs text-emerald-400 p-3 bg-emerald-950/30 border border-emerald-900/40 rounded-xl">Target ini memenuhi seluruh baseline kepatuhan OWASP.</p>`;
        }

        modalContent.innerHTML = `
            <div class="space-y-4">
                <div class="p-4 bg-slate-900/60 rounded-xl border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                        <h4 class="text-sm font-bold text-cyan-300 font-mono">${App.escapeHtml(item.target)}</h4>
                        <p class="text-xs text-slate-500">IP Ter-resolve: ${item.resolved_ip || 'Otomatis'}${item.direct_origin_ip ? ` <span class="text-cyan-400 font-semibold font-mono">(Direct Origin Bypass: ${item.direct_origin_ip})</span>` : ''} | Waktu: ${item.scanned_at || 'Selesai'}</p>
                    </div>
                    <div class="flex items-center space-x-2">
                        <span class="text-xs font-mono font-bold px-2.5 py-1 rounded-lg bg-black/40 text-slate-300 border border-white/5">
                            Skor OWASP: ${owasp.score || 0}/100 (${owasp.grade || 'N/A'})
                        </span>
                    </div>
                </div>

                ${advisoryHtml}

                <div class="space-y-2">
                    <h5 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                        <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                        <span>Hasil Engine PHP2Shell (CVE-2026-109618/19)</span>
                    </h5>
                    <div class="p-4 bg-black/60 border border-white/5 rounded-xl font-mono text-xs space-y-2 overflow-x-auto max-h-56">
                        <div class="flex items-center justify-between">
                            <span class="${p2s.vulnerable ? 'text-rose-400 font-bold' : (p2s.status === 'POTENTIALLY_VULNERABLE' ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold')}">
                                Status: ${App.escapeHtml(p2s.status || (p2s.vulnerable ? 'VULNERABLE' : 'SAFE'))}
                            </span>
                            ${p2s.php_version ? `<span class="text-[11px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">Versi PHP: ${App.escapeHtml(p2s.php_version)}</span>` : ''}
                        </div>
                        <p class="text-slate-300">Diagnosa: ${App.escapeHtml(p2s.reason || 'Tidak ada detail')}</p>
                        
                        <div class="mt-2 pt-2 border-t border-white/5 text-[11px] text-slate-400 space-y-1">
                            <div><strong>Engine Pemeriksa:</strong> OpenAI phpcheck.js & Assetnote Progressive Fuzzer</div>
                            ${p2s.probe?.verdict ? `<div><strong>Hasil Probe Crash:</strong> <span class="${p2s.probe.verdict === 'VULNERABLE' ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${App.escapeHtml(p2s.probe.verdict)}</span></div>` : ''}
                        </div>

                        ${p2s.evidence ? `<pre class="text-[11px] text-slate-400 whitespace-pre-wrap mt-2 p-2 bg-slate-950 rounded border border-white/5">${App.escapeHtml(typeof p2s.evidence === 'string' ? p2s.evidence : JSON.stringify(p2s.evidence, null, 2))}</pre>` : ''}
                    </div>
                </div>

                <div class="space-y-2">
                    <h5 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                        <span class="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                        <span>Daftar Temuan OWASP Top 10 & Server Hardening</span>
                    </h5>
                    <div class="max-h-60 overflow-y-auto space-y-2.5 pr-1">
                        ${findingsHtml}
                    </div>
                </div>
            </div>
        `;

        modal.classList.remove('hidden');
    },

    closeDetailModal() {
        const modal = document.getElementById('detail-modal');
        if (modal) modal.classList.add('hidden');
    },

    exportResultsJson() {
        if (!this.results.length) {
            App.showToast('Tidak ada data hasil scan untuk diekspor!', 'warning');
            return;
        }
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.results, null, 2));
        const a = document.createElement('a');
        a.setAttribute("href", dataStr);
        a.setAttribute("download", `audit_report_${new Date().toISOString().slice(0,10)}.json`);
        document.body.appendChild(a);
        a.click();
        a.remove();
        App.showToast('Laporan JSON berhasil diunduh.', 'success');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    window.Scanner.init();
});
