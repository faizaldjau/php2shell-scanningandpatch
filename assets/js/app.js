/**
 * Global Application Controller (Modern UI Edition)
 */

window.App = {
    currentTab: 'audit',

    init() {
        console.log('[Proj-PHP2Shell] SOC Dashboard Initialized.');
    },

    setTab(tabName) {
        this.currentTab = tabName;
        document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.nav-tab-btn').forEach(btn => {
            btn.className = "nav-tab-btn px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-200 flex items-center space-x-2";
        });

        const activeTarget = document.getElementById(`tab-${tabName}`);
        const activeBtn = document.getElementById(`tab-btn-${tabName}`);
        if (activeTarget) activeTarget.classList.remove('hidden');
        if (activeBtn) {
            activeBtn.className = "nav-tab-btn px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 shadow-sm transition-all duration-200 flex items-center space-x-2";
        }
    },

    copyText(text, btnElement = null) {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast('Berhasil disalin ke clipboard!', 'success');
            if (btnElement) {
                const originalText = btnElement.innerHTML;
                btnElement.innerHTML = `<svg class="w-3.5 h-3.5 inline mr-1 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg> <span>Tersalin!</span>`;
                setTimeout(() => { btnElement.innerHTML = originalText; }, 2000);
            }
        }).catch(err => {
            this.showToast('Gagal menyalin teks: ' + err, 'error');
        });
    },

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        const borderColor = type === 'success' ? 'border-emerald-500/60 bg-emerald-950/90 text-emerald-200' :
                           type === 'error' ? 'border-rose-500/60 bg-rose-950/90 text-rose-200' :
                           type === 'warning' ? 'border-amber-500/60 bg-amber-950/90 text-amber-200' :
                           'border-cyan-500/60 bg-cyan-950/90 text-cyan-200';

        toast.className = `p-3.5 rounded-xl border backdrop-blur-md shadow-2xl flex items-center justify-between text-xs transition-all duration-300 transform translate-y-3 opacity-0 pointer-events-auto ${borderColor}`;
        toast.innerHTML = `
            <div class="flex items-center space-x-2">
                <span class="w-1.5 h-1.5 rounded-full ${type === 'success' ? 'bg-emerald-400' : (type === 'error' ? 'bg-rose-400' : 'bg-cyan-400')}"></span>
                <span>${this.escapeHtml(message)}</span>
            </div>
            <button class="ml-3 text-slate-400 hover:text-white" onclick="this.parentElement.remove()">&times;</button>
        `;

        container.appendChild(toast);
        setTimeout(() => {
            toast.classList.remove('translate-y-3', 'opacity-0');
        }, 50);

        setTimeout(() => {
            toast.classList.add('opacity-0');
            setTimeout(() => toast.remove(), 350);
        }, 4000);
    },

    escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    window.App.init();
});
