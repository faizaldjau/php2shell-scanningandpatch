/**
 * In-Host SSH Auditor & Remediation Controller
 * SIPP Mahkamah Agung RI Edition (Surat Badilum No. 135/DJU.3/TI1.1.1/X/2026)
 */

window.SshAuditor = {
    isWorking: false,
    lastAuditData: null,
    pendingAction: null,

    init() {
        this.bindEvents();
    },

    bindEvents() {
        const form = document.getElementById('ssh-form');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.runAudit();
            });
        }
    },

    async runAudit() {
        if (this.isWorking) return;

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        if (!formData.get('host') || !formData.get('user')) {
            App.showToast('Host dan User SSH wajib diisi!', 'warning');
            return;
        }

        this.isWorking = true;
        this.updateBtnState('audit', true);
        this.clearTerminal();
        this.logTerminal('[*] Memulai koneksi SSH dan pemeriksaan internal server...');

        try {
            const resp = await fetch('api.php?action=ssh_audit', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('audit', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal melakukan audit via SSH', 'error');
                this.logTerminal(`[!] ERROR: ${res.error || 'Koneksi gagal'}`);
                return;
            }

            const data = res.data || {};
            this.lastAuditData = data;
            this.renderAuditResults(data);
            App.showToast('Audit internal via SSH selesai!', 'success');

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('audit', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    // =========================================================================
    // Patch Confirmation Modal & Dynamic Step Plan
    // =========================================================================

    showPatchConfirmationModal(type) {
        if (this.isWorking) return;
        this.pendingAction = type;

        const form = document.getElementById('ssh-form');
        const hostInput = form ? form.querySelector('[name="host"]') : null;
        const hostVal = (hostInput && hostInput.value.trim()) || '127.0.0.1';

        const modalHost = document.getElementById('patch-modal-host');
        const modalOs = document.getElementById('patch-modal-os');
        const modalPhp = document.getElementById('patch-modal-php');
        const modalTitle = document.getElementById('patch-modal-title');
        const modalBadge = document.getElementById('patch-modal-badge');
        const checklistContainer = document.getElementById('patch-modal-checklist');
        const btnExecLabel = document.getElementById('btn-modal-execute-label');

        const audit = this.lastAuditData || {};
        const osName = (audit.os_info && audit.os_info.name) || 'Linux Server';
        const phpVer = audit.php_cli_version || 'PHP CLI Runtime';

        if (modalHost) modalHost.innerText = hostVal;
        if (modalOs) modalOs.innerText = osName;
        if (modalPhp) modalPhp.innerText = phpVer;

        let title = 'Konfirmasi Penerapan Patch Keamanan';
        let badge = 'PATCH OTOMATIS';
        let execLabel = 'Ya, Terapkan Sekarang';
        let items = [];

        const isCentos = audit.is_centos7;
        const isUbuntu = audit.is_ubuntu_debian;
        const isRhel = audit.is_rhel_family;

        if (type === 'instant') {
            title = 'Konfirmasi Penerapan Patch Keamanan Instan (All-in-One)';
            badge = 'REMEDIASI LENGKAP';
            execLabel = '⚡ Terapkan Patch Keamanan Instan';

            let binaryStepDesc = 'Memperbarui paket biner PHP resmi ke versi ter-patch via manajer paket sistem operasi.';
            if (isCentos) {
                binaryStepDesc = 'Memasang paket biner patch resmi Mahkamah Agung RI (<code>php-5.6-mari-centos7-20261024.tar.gz</code> dari <code>s.id/cvemari</code>) sesuai Surat Badilum No. 135/DJU.3/TI1.1.1/X/2026.';
            } else if (isUbuntu) {
                binaryStepDesc = 'Mengunduh dan memasang paket biner PHP aman terbaru dari repositori resmi Ubuntu via <code>apt-get --only-upgrade install php*</code>.';
            } else if (isRhel) {
                binaryStepDesc = 'Memperbarui paket biner PHP aman via repositori Enterprise Linux (<code>dnf/yum upgrade php php-fpm</code>).';
            }

            items = [
                {
                    step: 1,
                    title: 'Pencadangan Otomatis Berkas Konfigurasi (Auto-Backup)',
                    desc: 'Mencadangkan seluruh berkas <code>php.ini</code> dan modul aktif ke berkas backup bertanda waktu (<code>php.ini.bak.&lt;timestamp&gt;</code>) sebelum modifikasi dilakukan.'
                },
                {
                    step: 2,
                    title: 'Pembaruan Biner Mesin PHP (Binary Engine Patching)',
                    desc: binaryStepDesc
                },
                {
                    step: 3,
                    title: 'Penguncian Parameter Proteksi php.ini (Hardening)',
                    desc: 'Mematikan <code>session.upload_progress.enabled = Off</code> (menghilangkan vektor alokasi memori beracun), membatasi <code>max_input_nesting_level = 16</code> (mencegah DoS / nesting exhaust), serta menonaktifkan <code>display_errors</code> dan <code>expose_php</code>.'
                },
                {
                    step: 4,
                    title: 'Pemuatan Ulang Layanan (Graceful Service Reload)',
                    desc: 'Memuat ulang web server (<code>httpd</code> / <code>apache2</code>) dan <code>php-fpm</code> yang sedang aktif secara aman tanpa memutus sesi basis data perkara SIPP.'
                },
                {
                    step: 5,
                    title: 'Verifikasi Keamanan Pasca-Patch (Post-Verification)',
                    desc: 'Mengeksekusi probe internal pasca-instalasi untuk memastikan biner ter-patch aktif dan parameter runtime telah terkunci 100% aman.'
                }
            ];
        } else if (type === 'mari') {
            title = 'Konfirmasi Pemasangan Patch Biner Resmi Mahkamah Agung RI';
            badge = 'PATCH RESMI MA-RI';
            execLabel = 'Pasang Patch Biner MA-RI';
            items = [
                {
                    step: 1,
                    title: 'Unduh Arsip Biner Resmi Badilum MA-RI',
                    desc: 'Mengambil paket <code>php-5.6-mari-centos7-20261024.tar.gz</code> dari server resmi MA-RI (<code>office.pt-yogyakarta.go.id</code> / <code>s.id/cvemari</code>).'
                },
                {
                    step: 2,
                    title: 'Backup Biner PHP & Modul Apache Lama',
                    desc: 'Mencadangkan berkas biner <code>/usr/bin/php</code> dan modul <code>libphp5.so</code> Apache yang lama.'
                },
                {
                    step: 3,
                    title: 'Ekstraksi dan Pemasangan Biner SIPP Ter-patch',
                    desc: 'Memasang biner PHP 5.6 yang telah diperbaiki memory parser Zend heap-nya (identifikasi: <em>Custom Built MA RI: 2026-10-24</em>).'
                },
                {
                    step: 4,
                    title: 'Restart Layanan & Verifikasi Header',
                    desc: 'Memuat ulang web server <code>httpd</code> dan menjalankan <code>php -v</code> untuk memvalidasi tanda tangan biner resmi MA-RI.'
                }
            ];
        } else if (type === 'distro') {
            title = 'Konfirmasi Pembaruan Paket Keamanan Distro';
            badge = isUbuntu ? 'APT UPGRADE (UBUNTU)' : 'DNF UPGRADE (ENTERPRISE)';
            execLabel = 'Jalankan Pembaruan Paket Distro';
            items = [
                {
                    step: 1,
                    title: 'Sinkronisasi Repositori Resmi Sistem Operasi',
                    desc: `Menjalankan pembaruan metadata paket keamanan terbaru dari repositori resmi ${isUbuntu ? 'Ubuntu Canonical' : 'RHEL/AlmaLinux'}.`
                },
                {
                    step: 2,
                    title: 'Pembaruan Paket PHP & Modul Terkait',
                    desc: 'Mengunduh dan memperbarui biner PHP, CLI, dan FastCGI (FPM) ke versi rilis keamanan yang telah menutup kerentanan PHP2Shell.'
                },
                {
                    step: 3,
                    title: 'Pemuatan Ulang Service Web & PHP-FPM',
                    desc: 'Memuat ulang layanan server agar proses worker menggunakan biner PHP yang baru diperbarui.'
                }
            ];
        } else if (type === 'harden') {
            title = 'Konfirmasi Penguncian Konfigurasi php.ini';
            badge = 'HARDENING KONFIGURASI';
            execLabel = 'Kunci Parameter php.ini';
            items = [
                {
                    step: 1,
                    title: 'Pencadangan Berkas php.ini',
                    desc: 'Menyimpan salinan arsip konfigurasi asli sebelum disunting (<code>php.ini.bak.&lt;timestamp&gt;</code>).'
                },
                {
                    step: 2,
                    title: 'Nonaktifkan session.upload_progress.enabled',
                    desc: 'Menyetel <code>session.upload_progress.enabled = Off</code> untuk menutup jalur injeksi struktur heap sesi.'
                },
                {
                    step: 3,
                    title: 'Pembatasan max_input_nesting_level',
                    desc: 'Menyetel <code>max_input_nesting_level = 16</code> guna membatasi kedalaman struktur hash payload.'
                },
                {
                    step: 4,
                    title: 'Penyembunyian Jejak Informasi Versi',
                    desc: 'Menyetel <code>display_errors = Off</code> dan <code>expose_php = Off</code>.'
                },
                {
                    step: 5,
                    title: 'Pemuatan Ulang Konfigurasi Layanan',
                    desc: 'Me-reload Apache/PHP-FPM agar nilai parameter baru langsung diterapkan pada proses runtime.'
                }
            ];
        }

        if (modalTitle) modalTitle.innerText = title;
        if (modalBadge) modalBadge.innerText = badge;
        if (btnExecLabel) btnExecLabel.innerText = execLabel;

        if (checklistContainer) {
            checklistContainer.innerHTML = items.map(item => `
                <div class="flex items-start space-x-3 p-3 bg-slate-900/40 rounded-xl border border-white/5 hover:border-emerald-500/30 transition">
                    <div class="w-6 h-6 rounded-lg bg-emerald-500/10 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center shrink-0 border border-emerald-500/20">
                        ${item.step}
                    </div>
                    <div class="flex-grow space-y-0.5">
                        <div class="text-xs font-semibold text-slate-200">${item.title}</div>
                        <div class="text-[11px] text-slate-400 leading-relaxed">${item.desc}</div>
                    </div>
                </div>
            `).join('');
        }

        const modal = document.getElementById('patch-confirm-modal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    },

    closePatchModal() {
        const modal = document.getElementById('patch-confirm-modal');
        if (modal) {
            modal.classList.add('hidden');
        }
        this.pendingAction = null;
    },

    confirmAndExecutePatch() {
        const action = this.pendingAction;
        this.closePatchModal();

        if (action === 'instant') {
            this.executeInstantPatch();
        } else if (action === 'mari') {
            this.executeMariPatch(true);
        } else if (action === 'distro') {
            this.executeDistroUpgrade(true);
        } else if (action === 'harden') {
            this.executeHardening(true);
        }
    },

    // =========================================================================
    // Emergency Quarantine & Incident Eradication Methods
    // =========================================================================

    showQuarantineModal() {
        if (this.isWorking) return;
        const modal = document.getElementById('quarantine-confirm-modal');
        if (modal) modal.classList.remove('hidden');
    },

    closeQuarantineModal() {
        const modal = document.getElementById('quarantine-confirm-modal');
        if (modal) modal.classList.add('hidden');
    },

    async executeQuarantine() {
        if (this.isWorking) return;
        this.closeQuarantineModal();

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        if (!formData.get('host') || !formData.get('user')) {
            App.showToast('Host dan User SSH wajib diisi!', 'warning');
            return;
        }

        this.isWorking = true;
        this.updateBtnState('quarantine', true);
        this.logTerminal('\n============================================================');
        this.logTerminal('[*] MEMULAI PROSEDUR TANGGAP DARURAT & KARANTINA INSIDEN...');
        this.logTerminal('[*] Sesi Beracun -> Webshell Upload -> Kill Reverse Shells');
        this.logTerminal('============================================================');

        try {
            const resp = await fetch('api.php?action=ssh_quarantine', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('quarantine', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal mengeksekusi karantina', 'error');
                this.logTerminal(`[!] QUARANTINE ERROR: ${res.error}`);
                return;
            }

            const data = res.data || {};
            const logs = data.logs || [];
            logs.forEach(line => this.logTerminal(line));

            App.showToast('Tindakan Tanggap Darurat & Karantina Berhasil Dieksekusi!', 'success');

            // Refresh audit to re-evaluate telemetry
            this.runAudit();

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('quarantine', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    // =========================================================================
    // Patch Execution Methods
    // =========================================================================

    async executeInstantPatch() {
        if (this.isWorking) return;

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        if (!formData.get('host') || !formData.get('user')) {
            App.showToast('Host dan User SSH wajib diisi!', 'warning');
            return;
        }

        this.isWorking = true;
        this.updateBtnState('instant_patch', true);
        this.logTerminal('\n============================================================');
        this.logTerminal('[*] MEMULAI PENERAPAN PATCH KEAMANAN INSTAN (ALL-IN-ONE)...');
        this.logTerminal('[*] Backup -> Binary Patch/Upgrade -> Hardening php.ini -> Verify');
        this.logTerminal('============================================================');

        try {
            const resp = await fetch('api.php?action=ssh_instant_patch', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('instant_patch', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal menerapkan patch keamanan instan', 'error');
                this.logTerminal(`[!] PATCH ERROR: ${res.error}`);
                return;
            }

            const logs = (res.data && res.data.logs) || [];
            logs.forEach(line => this.logTerminal(line));

            App.showToast('Patch Keamanan Instan Berhasil Diterapkan & Terverifikasi!', 'success');

            // Refresh audit to update all cards and telemetry
            this.runAudit();

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('instant_patch', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    async executeMariPatch(skipConfirm = false) {
        if (this.isWorking) return;

        if (!skipConfirm) {
            this.showPatchConfirmationModal('mari');
            return;
        }

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        this.isWorking = true;
        this.updateBtnState('mari_patch', true);
        this.logTerminal('\n============================================================');
        this.logTerminal('[*] MEMULAI INSTALASI PATCH BINER RESMI MAHKAMAH AGUNG RI...');
        this.logTerminal('[*] Target: CentOS 7 SIPP (s.id/cvemari)');
        this.logTerminal('============================================================');

        try {
            const resp = await fetch('api.php?action=ssh_mari_patch', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('mari_patch', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal memasang patch MA-RI', 'error');
                this.logTerminal(`[!] PATCH ERROR: ${res.error}`);
                return;
            }

            const logs = (res.data && res.data.logs) || [];
            logs.forEach(line => this.logTerminal(line));

            if (res.data && res.data.is_mari_patched) {
                App.showToast('Patch Biner Resmi MA-RI Berhasil Dipasang & Terverifikasi!', 'success');
            } else {
                App.showToast('Instalasi selesai. Periksa log verifikasi di terminal.', 'info');
            }

            // Refresh audit after patching
            this.runAudit();

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('mari_patch', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    async executeDistroUpgrade(skipConfirm = false) {
        if (this.isWorking) return;

        if (!skipConfirm) {
            this.showPatchConfirmationModal('distro');
            return;
        }

        const isUbuntu = this.lastAuditData && this.lastAuditData.is_ubuntu_debian;
        const mgrName = isUbuntu ? 'APT (Ubuntu/Debian)' : 'DNF/YUM (Enterprise Linux)';

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        this.isWorking = true;
        this.updateBtnState('distro_upgrade', true);
        this.logTerminal('\n============================================================');
        this.logTerminal(`[*] MEMULAI UPDATE KEAMANAN PAKET PHP DISTRO (${mgrName})...`);
        this.logTerminal('============================================================');

        try {
            const resp = await fetch('api.php?action=ssh_distro_upgrade', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('distro_upgrade', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal menjalankan pembaruan paket distro', 'error');
                this.logTerminal(`[!] UPGRADE ERROR: ${res.error}`);
                return;
            }

            const logs = (res.data && res.data.logs) || [];
            logs.forEach(line => this.logTerminal(line));

            App.showToast('Pembaruan paket keamanan distro selesai dieksekusi!', 'success');

            // Refresh audit after upgrading
            this.runAudit();

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('distro_upgrade', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    async executeCompromiseCheck() {
        if (this.isWorking) return;

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        this.isWorking = true;
        this.updateBtnState('compromise', true);
        this.logTerminal('\n============================================================');
        this.logTerminal('[*] MEMULAI PEMERIKSAAN JEJAK PENYUSUPAN / WEBSHELL (IoC)...');
        this.logTerminal('============================================================');

        try {
            const resp = await fetch('api.php?action=ssh_check_compromise', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('compromise', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal memeriksa jejak penyusupan', 'error');
                this.logTerminal(`[!] ERROR: ${res.error}`);
                return;
            }

            const data = res.data || {};
            const logs = data.logs || [];
            logs.forEach(line => this.logTerminal(line));

            this.renderCompromiseResults(data);

            if (data.compromise_detected) {
                App.showToast('PERINGATAN: Terdeteksi indikasi jejak penyusupan pada server!', 'error');
            } else {
                App.showToast('Status Bersih: Tidak ditemukan jejak penyusupan atau webshell.', 'success');
            }

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('compromise', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    async executeHardening(skipConfirm = false) {
        if (this.isWorking) return;

        if (!skipConfirm) {
            this.showPatchConfirmationModal('harden');
            return;
        }

        const form = document.getElementById('ssh-form');
        const formData = new FormData(form);

        this.isWorking = true;
        this.updateBtnState('harden', true);
        this.logTerminal('\n========================================');
        this.logTerminal('[*] MEMULAI HARDENING KONFIGURASI php.ini...');
        this.logTerminal('========================================');

        try {
            const resp = await fetch('api.php?action=ssh_harden', {
                method: 'POST',
                body: formData
            });
            const res = await resp.json();

            this.isWorking = false;
            this.updateBtnState('harden', false);

            if (!res.success) {
                App.showToast(res.error || 'Gagal menjalankan hardening', 'error');
                this.logTerminal(`[!] HARDENING ERROR: ${res.error}`);
                return;
            }

            const logs = (res.data && res.data.logs) || [];
            logs.forEach(line => this.logTerminal(line));

            App.showToast('Hardening konfigurasi php.ini berhasil dieksekusi!', 'success');
            // Refresh audit after hardening
            this.runAudit();

        } catch (err) {
            this.isWorking = false;
            this.updateBtnState('harden', false);
            App.showToast('Kesalahan jaringan: ' + err, 'error');
            this.logTerminal(`[!] NETWORK ERROR: ${err}`);
        }
    },

    renderAuditResults(data) {
        const resultPanel = document.getElementById('ssh-audit-results');
        const actionBox = document.getElementById('ssh-action-box');
        if (resultPanel) resultPanel.classList.remove('hidden');
        if (actionBox) actionBox.classList.remove('hidden');

        // OS Badge
        const osEl = document.getElementById('ssh-res-os');
        if (osEl) osEl.innerText = `${data.os_info.name || 'Linux'} (${data.os_info.id || ''} ${data.os_info.version || ''})`;

        // PHP CLI
        const phpEl = document.getElementById('ssh-res-php');
        if (phpEl) phpEl.innerText = data.php_cli_version || 'N/A';

        // Dynamic Action Button Visibility based on Operating System
        const btnMari = document.getElementById('btn-ssh-mari-patch');
        const btnDistro = document.getElementById('btn-ssh-distro-upgrade');
        const btnDistroLabel = document.getElementById('btn-ssh-distro-upgrade-label');

        if (data.is_centos7) {
            if (btnMari) btnMari.classList.remove('hidden');
            if (btnDistro) btnDistro.classList.add('hidden');
        } else if (data.is_ubuntu_debian) {
            if (btnMari) btnMari.classList.add('hidden');
            if (btnDistro) {
                btnDistro.classList.remove('hidden');
                if (btnDistroLabel) btnDistroLabel.innerText = 'Update Keamanan (APT)';
            }
        } else if (data.is_rhel_family) {
            if (btnMari) btnMari.classList.add('hidden');
            if (btnDistro) {
                btnDistro.classList.remove('hidden');
                if (btnDistroLabel) btnDistroLabel.innerText = 'Update Keamanan (DNF)';
            }
        } else {
            if (btnMari) btnMari.classList.add('hidden');
            if (btnDistro) btnDistro.classList.add('hidden');
        }

        // Security Patch Status Badge
        const mariStatusEl = document.getElementById('ssh-res-mari-status');
        if (mariStatusEl) {
            if (data.is_mari_patched) {
                mariStatusEl.innerHTML = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span><span>PATCH RESMI MA-RI AKTIF</span></span>`;
            } else if (data.is_centos7) {
                mariStatusEl.innerHTML = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center space-x-1 animate-pulse"><span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span><span>BELUM PATCH MA-RI</span></span>`;
            } else if (data.is_ubuntu_debian) {
                mariStatusEl.innerHTML = data.is_patched ? 
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span><span>UBUNTU / APT (AMAN)</span></span>` :
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center space-x-1"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span><span>UBUNTU (PERLU APT UPGRADE)</span></span>`;
            } else if (data.is_rhel_family) {
                mariStatusEl.innerHTML = data.is_patched ?
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span><span>RHEL / DNF (AMAN)</span></span>` :
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center space-x-1"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span><span>RHEL (PERLU DNF UPGRADE)</span></span>`;
            } else {
                mariStatusEl.innerHTML = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-white/5">DISTRO STANDARD</span>`;
            }
        }

        // Dynamic System Banner (CentOS 7 SIPP specific vs Ubuntu/Debian Standard)
        const mariBanner = document.getElementById('ssh-mari-banner');
        const mariTitle = document.getElementById('ssh-mari-banner-title');
        const mariDesc = document.getElementById('ssh-mari-banner-desc');

        if (mariBanner && data.is_centos7) {
            mariBanner.classList.remove('hidden');
            if (data.is_mari_patched) {
                mariBanner.className = "p-4 rounded-xl border border-emerald-500/50 bg-emerald-950/40 text-emerald-200 space-y-1.5";
                if (mariTitle) mariTitle.innerHTML = `<span class="text-emerald-400 font-bold">✓ SERVER SIPP TERLINDUNGI — PATCH RESMI MA-RI AKTIF</span>`;
                if (mariDesc) mariDesc.innerHTML = `Biner PHP telah terpasang paket resmi kustom <strong>(Custom Built MA RI: 2026-10-24)</strong> sesuai rujukan Surat Ditjen Badilum No. 135/DJU.3/TI1.1.1/X/2026.`;
            } else {
                mariBanner.className = "p-4 rounded-xl border border-rose-500/50 bg-rose-950/40 text-rose-200 space-y-1.5";
                if (mariTitle) mariTitle.innerHTML = `<span class="text-rose-400 font-bold">⚠️ PERINGATAN: SERVER SIPP CENTOS 7 TERDETEKSI (LEVEL BERBAHAYA)</span>`;
                if (mariDesc) mariDesc.innerHTML = `Sesuai Surat Ditjen Badilum No. 135/DJU.3/TI1.1.1/X/2026, server SIPP CentOS 7 dengan PHP 5.4/5.6 wajib segera dimitigasi. Silakan klik tombol <strong>'Pasang Patch MA-RI'</strong> di bawah untuk memasang paket biner resmi.`;
            }
        } else if (mariBanner && data.is_ubuntu_debian) {
            mariBanner.classList.remove('hidden');
            mariBanner.className = "p-4 rounded-xl border border-blue-500/40 bg-blue-950/30 text-blue-200 space-y-1.5";
            if (mariTitle) mariTitle.innerHTML = `<span class="text-cyan-400 font-bold flex items-center space-x-1.5"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg><span>SERVER UBUNTU / DEBIAN TERDETEKSI (BUKAN CENTOS 7)</span></span>`;
            if (mariDesc) mariDesc.innerHTML = `Server terdeteksi berjalan pada <strong>${App.escapeHtml(data.os_info.name || 'Ubuntu')}</strong> dengan PHP modern. <em>Patch biner CentOS 7 MA-RI (Surat No. 135) tidak berlaku di sistem ini</em>. Pembaruan keamanan dilakukan melalui repositori resmi Ubuntu (APT) menggunakan tombol <strong>'Update Keamanan (APT)'</strong> atau kunci parameter <code>php.ini</code>.`;
        } else if (mariBanner && data.is_rhel_family) {
            mariBanner.classList.remove('hidden');
            mariBanner.className = "p-4 rounded-xl border border-indigo-500/40 bg-indigo-950/30 text-indigo-200 space-y-1.5";
            if (mariTitle) mariTitle.innerHTML = `<span class="text-indigo-300 font-bold flex items-center space-x-1.5"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg><span>SERVER ENTERPRISE LINUX TERDETEKSI</span></span>`;
            if (mariDesc) mariDesc.innerHTML = `Server terdeteksi berjalan pada <strong>${App.escapeHtml(data.os_info.name || 'AlmaLinux/RHEL')}</strong>. Pembaruan biner keamanan PHP dilakukan via DNF/YUM menggunakan tombol <strong>'Update Keamanan (DNF)'</strong> atau kunci parameter <code>php.ini</code>.`;
        } else if (mariBanner) {
            mariBanner.classList.add('hidden');
        }

        // Status Upload Progress
        const upEl = document.getElementById('ssh-res-upload-progress');
        const upVal = (data.runtime_settings['session.upload_progress.enabled'] || 'UNKNOWN').toLowerCase();
        if (upEl) {
            if (['off', '0', 'no'].includes(upVal)) {
                upEl.innerHTML = `<span class="px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono font-bold"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block mr-1"></span>DISABLED (AMAN)</span>`;
            } else {
                upEl.innerHTML = `<span class="px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] font-mono font-bold glow-rose animate-pulse"><span class="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block mr-1"></span>ENABLED (RENTAN PHP2SHELL)</span>`;
            }
        }

        // Nesting Level
        const nestEl = document.getElementById('ssh-res-nesting');
        const nestVal = data.runtime_settings['max_input_nesting_level'] || '64 (Default)';
        if (nestEl) {
            nestEl.innerHTML = (parseInt(nestVal) <= 32) ? 
                `<span class="text-emerald-400 font-bold">${nestVal} (TERKUNCI)</span>` : 
                `<span class="text-amber-400 font-bold">${nestVal} (RAWAN FUZZING)</span>`;
        }

        // 4-Condition Assessment for CVE-2026-115560
        const cve11 = data.cve_2026_115560 || {};
        const badgeEl = document.getElementById('ssh-cve115560-badge');
        const condHandler = document.getElementById('cve-cond-handler');
        const condApp = document.getElementById('cve-cond-app');
        const condStart = document.getElementById('cve-cond-start');
        const condUpload = document.getElementById('cve-cond-upload');
        const condNotes = document.getElementById('cve-cond-notes');

        if (condHandler) condHandler.innerText = cve11.serialize_handler || 'php';
        if (condApp) {
            condApp.innerHTML = cve11.app_override_detected ? 
                '<span class="text-rose-400 font-bold">Ditemukan (ini_set)</span>' : 
                '<span class="text-emerald-400">Tidak Ditemukan</span>';
        }
        if (condStart) condStart.innerText = 'Sebelum session_start()';
        if (condUpload) {
            condUpload.innerHTML = cve11.upload_progress_enabled ? 
                '<span class="text-rose-400 font-bold">Aktif (On)</span>' : 
                '<span class="text-emerald-400 font-bold">Nonaktif (Off)</span>';
        }

        if (badgeEl) {
            if (cve11.risk_verdict === 'PROTECTED') {
                badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
                badgeEl.innerText = "TERLINDUNGI (VEKTOR LUMPUH)";
            } else if (cve11.risk_verdict === 'CRITICAL_VULNERABLE') {
                badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse";
                badgeEl.innerText = "CRITICAL: MEMENUHI 4 KONDISI";
            } else if (cve11.risk_verdict === 'POTENTIALLY_AT_RISK') {
                badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30";
                badgeEl.innerText = "PERLU MITIGASI UPLOAD PROGRESS";
            } else {
                badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400";
                badgeEl.innerText = "AMAN";
            }
        }

        if (condNotes) {
            condNotes.innerHTML = `<strong>Keterangan Advisori:</strong> ${App.escapeHtml(cve11.verdict_reason || 'Pemeriksaan 4 kondisi selesai.')}`;
        }

        // Services
        const srvEl = document.getElementById('ssh-res-services');
        if (srvEl) {
            const srvs = Object.keys(data.services || {});
            srvEl.innerText = srvs.length ? srvs.join(', ') : 'Tidak ada service terdeteksi';
        }

        // Log to terminal
        if (data.raw_logs) {
            data.raw_logs.forEach(l => this.logTerminal(l));
        }
    },

    renderCompromiseResults(data) {
        const banner = document.getElementById('ssh-comp-banner');
        const titleEl = document.getElementById('ssh-comp-title');
        const contentEl = document.getElementById('ssh-comp-content');
        if (!banner || !contentEl) return;

        banner.classList.remove('hidden');

        if (data.compromise_detected) {
            banner.className = "p-4 rounded-xl border border-rose-500/50 bg-rose-950/60 text-rose-200 space-y-2";
            if (titleEl) titleEl.innerHTML = `<span class="text-rose-400 font-bold flex items-center space-x-1.5"><svg class="w-4 h-4 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg><span>PERINGATAN: TERDETEKSI JEJAK PENYUSUPAN / FILE MENCURIGAKAN!</span></span>`;
            
            const listHtml = (data.indicators || []).map(ind => `
                <div class="p-2.5 bg-black/60 rounded-lg border border-rose-500/30 space-y-1">
                    <div class="font-bold text-white text-[11px]">${App.escapeHtml(ind.title)}</div>
                    <pre class="font-mono text-[10px] text-rose-300 whitespace-pre-wrap">${App.escapeHtml(ind.details)}</pre>
                </div>
            `).join('');

            contentEl.innerHTML = listHtml;
        } else {
            banner.className = "p-4 rounded-xl border border-emerald-500/50 bg-emerald-950/40 text-emerald-200 space-y-1.5";
            if (titleEl) titleEl.innerHTML = `<span class="text-emerald-400 font-bold">✓ HASIL ANALISIS JEJAK PENYUSUPAN: BERSIH</span>`;
            contentEl.innerHTML = `<p class="text-xs text-emerald-300">Tidak ditemukan berkas sesi beracun di <code>/var/lib/php/session</code>, tidak ada berkas skrip PHP liar di folder upload berkas perkara SIPP, dan tidak ada jejak eksploitasi di access log.</p>`;
        }
    },

    updateBtnState(type, loading) {
        const btnAudit = document.getElementById('btn-ssh-audit');
        const btnInstant = document.getElementById('btn-ssh-instant-patch');
        const btnMari = document.getElementById('btn-ssh-mari-patch');
        const btnDistro = document.getElementById('btn-ssh-distro-upgrade');
        const btnComp = document.getElementById('btn-ssh-compromise');
        const btnHarden = document.getElementById('btn-ssh-harden');
        const btnQuarantine = document.getElementById('btn-ssh-quarantine');
        const btnModalQuarantine = document.getElementById('btn-modal-execute-quarantine');
        const btnModalExec = document.getElementById('btn-modal-execute-patch');

        if (type === 'instant_patch') {
            if (btnInstant) {
                btnInstant.disabled = loading;
                btnInstant.innerHTML = loading ? `
                    <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>Menerapkan Patch Keamanan Instan...</span>
                ` : `
                    <svg class="w-4 h-4 text-emerald-200 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                    <span>⚡ Terapkan Patch Keamanan Instan (Full Remediasi + Hardening)</span>
                `;
            }
            if (btnModalExec) {
                btnModalExec.disabled = loading;
            }
        }

        if (type === 'audit' && btnAudit) {
            btnAudit.disabled = loading;
            btnAudit.innerHTML = loading ? `
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Memeriksa via SSH...
            ` : `
                <svg class="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg> Jalankan Audit SSH Internal (Read-Only)
            `;
        }

        if (type === 'mari_patch' && btnMari) {
            btnMari.disabled = loading;
            btnMari.innerHTML = loading ? `
                <svg class="animate-spin -ml-1 mr-1 h-3.5 w-3.5 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Memasang Patch...
            ` : `
                <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                <span class="truncate">Pasang Patch MA-RI</span>
            `;
        }

        if (type === 'distro_upgrade' && btnDistro) {
            btnDistro.disabled = loading;
            btnDistro.innerHTML = loading ? `
                <svg class="animate-spin -ml-1 mr-1 h-3.5 w-3.5 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Memperbarui Paket...
            ` : `
                <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                <span id="btn-ssh-distro-upgrade-label" class="truncate">${(this.lastAuditData && this.lastAuditData.is_ubuntu_debian) ? 'Update Keamanan (APT)' : 'Update Keamanan (DNF)'}</span>
            `;
        }

        if (type === 'compromise' && btnComp) {
            btnComp.disabled = loading;
            btnComp.innerHTML = loading ? `
                <svg class="animate-spin -ml-1 mr-1 h-3.5 w-3.5 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Memindai IoC...
            ` : `
                <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                <span class="truncate">Cek Jejak Penyusupan</span>
            `;
        }

        if (type === 'harden' && btnHarden) {
            btnHarden.disabled = loading;
            btnHarden.innerHTML = loading ? `
                <svg class="animate-spin -ml-1 mr-1 h-3.5 w-3.5 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Mengunci php.ini...
            ` : `
                <svg class="w-4 h-4 shrink-0 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                <span class="truncate">Kunci php.ini</span>
            `;
        }

        if (type === 'quarantine') {
            if (btnQuarantine) {
                btnQuarantine.disabled = loading;
                btnQuarantine.innerHTML = loading ? `
                    <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>Mengeksekusi Karantina & Pembersihan...</span>
                ` : `
                    <svg class="w-4 h-4 text-rose-300 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    <span>🚨 Tindakan Tanggap Darurat: Karantina Sesi Beracun & Netralkan Webshell</span>
                `;
            }
            if (btnModalQuarantine) {
                btnModalQuarantine.disabled = loading;
            }
        }
    },

    clearTerminal() {
        const term = document.getElementById('ssh-terminal-log');
        if (term) term.innerText = '';
    },

    logTerminal(text) {
        const term = document.getElementById('ssh-terminal-log');
        if (term) {
            term.innerText += text + '\n';
            term.scrollTop = term.scrollHeight;
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    window.SshAuditor.init();
});
