/**
 * Safe PoC Penetration Simulation Demo Controller
 */

window.DemoSimulator = {
    isRunning: false,
    timerInterval: null,
    startTime: null,

    setTarget(url) {
        const input = document.getElementById('demo-target-url');
        if (input) {
            input.value = url;
            input.focus();
            App.showToast(`Target diatur ke: ${url}`, 'info');
        }
    },

    async runDemo(e) {
        if (e) e.preventDefault();
        if (this.isRunning) return;

        const input = document.getElementById('demo-target-url');
        const targetUrl = (input ? input.value : '').trim();

        if (!targetUrl) {
            App.showToast('Harap masukkan URL atau Host target!', 'warning');
            return;
        }

        this.isRunning = true;
        this.updateUI(true);
        this.resetCanvas();

        const stageBox = document.getElementById('demo-stage-box');
        const stageText = document.getElementById('demo-stage-text');
        const stageBar = document.getElementById('demo-stage-bar');
        const stageTimer = document.getElementById('demo-stage-timer');

        if (stageBox) stageBox.classList.remove('hidden');
        if (stageText) stageText.innerText = 'Tahap 1/3: Memeriksa Gerbang Pre-Flight (DNS & Port)...';
        if (stageBar) stageBar.style.width = '30%';

        this.startTime = Date.now();
        this.timerInterval = setInterval(() => {
            if (stageTimer && this.startTime) {
                const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
                stageTimer.innerText = `${elapsed}s`;
            }
        }, 100);

        // Stage 2 update timer
        setTimeout(() => {
            if (this.isRunning && stageText && stageBar) {
                stageText.innerText = 'Tahap 2/3: Menjalankan Safe Memory Fuzzer (Zend Probe 1)...';
                stageBar.style.width = '65%';
            }
        }, 600);

        try {
            const formData = new FormData();
            formData.append('target_url', targetUrl);
            const originIp = document.getElementById('demo-origin-ip')?.value?.trim();
            if (originIp) {
                formData.append('origin_ip', originIp);
            }

            const resp = await fetch('api.php?action=demo_test', {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();

            if (stageText && stageBar) {
                stageText.innerText = 'Tahap 3/3: Menganalisis Bukti Respon Crash Memori...';
                stageBar.style.width = '100%';
            }

            // Brief delay to show completion stage smoothly
            await new Promise(r => setTimeout(r, 400));

            this.renderResult(data);
        } catch (err) {
            App.showToast('Gagal menjalankan simulasi: ' + err, 'error');
            const idle = document.getElementById('demo-state-idle');
            if (idle) idle.classList.remove('hidden');
        } finally {
            this.isRunning = false;
            this.updateUI(false);
            if (this.timerInterval) clearInterval(this.timerInterval);
            if (stageBox) stageBox.classList.add('hidden');
        }
    },

    resetCanvas() {
        ['demo-state-idle', 'demo-state-vulnerable', 'demo-state-protected', 'demo-state-unreachable'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });
    },

    renderResult(data) {
        this.resetCanvas();

        if (!data.success) {
            App.showToast(data.error || 'Terjadi kesalahan sistem saat simulasi', 'error');
            const idle = document.getElementById('demo-state-idle');
            if (idle) idle.classList.remove('hidden');
            return;
        }

        if (data.reachable === false) {
            const el = document.getElementById('demo-state-unreachable');
            const titleEl = document.getElementById('demo-unreach-title');
            const msgEl = document.getElementById('demo-unreach-msg');

            if (titleEl) titleEl.innerText = data.alert_subtitle || 'Target Tidak Dapat Dijangkau';
            if (msgEl) msgEl.innerText = data.action_message || 'Domain tidak dapat di-resolve atau port ditutup.';
            if (el) el.classList.remove('hidden');
            App.showToast('Simulasi berhenti: Target offline.', 'warning');
            return;
        }

        if (data.status === 'VULNERABLE' || data.status === 'POTENTIALLY_VULNERABLE') {
            const el = document.getElementById('demo-state-vulnerable');
            const titleEl = document.getElementById('demo-vuln-title');
            const subEl = document.getElementById('demo-vuln-subtitle');
            const verEl = document.getElementById('demo-php-ver');
            const evEl = document.getElementById('demo-vuln-evidence');

            if (titleEl) {
                titleEl.innerText = data.status === 'VULNERABLE' ? 
                    'PENETRASI BERHASIL DILAKUKAN — SEGERA LAKUKAN PATCH!' : 
                    'VERSI PHP RENTAN TERDETEKSI — SEGERA LAKUKAN HARDENING!';
            }
            if (subEl) subEl.innerText = data.alert_subtitle;
            if (verEl) {
                let verText = `PHP Versi: ${data.php_version || 'Unknown'}`;
                if (data.direct_origin_ip) {
                    verText += ` (Direct Origin: ${data.direct_origin_ip})`;
                } else if (data.redirected_to) {
                    verText += ` (HTTP ➔ HTTPS Redirected)`;
                }
                verEl.innerText = verText;
            }
            if (evEl) {
                evEl.innerText = typeof data.evidence === 'string' ? data.evidence : JSON.stringify(data.evidence || data.reason, null, 2);
            }
            if (el) el.classList.remove('hidden');
            App.showToast('Simulasi Selesai: Celah PHP2Shell Berhasil Dikonfirmasi!', 'error');
            return;
        }

        // Protected State
        const elProt = document.getElementById('demo-state-protected');
        const subProt = document.getElementById('demo-prot-subtitle');
        if (subProt) subProt.innerText = data.alert_subtitle || 'Server tidak memicu crash memori pada payload probe.';
        if (elProt) elProt.classList.remove('hidden');
        App.showToast('Simulasi Selesai: Server terlindungi dari PHP2Shell.', 'success');
    },

    updateUI(running) {
        const btn = document.getElementById('btn-run-demo');
        if (btn) {
            btn.disabled = running;
            btn.innerHTML = running ? `
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> <span>Sedang Melakukan Uji Penetrasi Aman...</span>
            ` : `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path></svg> <span>Jalankan Simulasi Penetrasi Aman</span>
            `;
        }
    }
};
