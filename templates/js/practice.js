let theme = localStorage.getItem('theme') || 'dark';

function toggleTheme() {
    const body = document.body;
    const icon = document.getElementById('themeIcon');
    
    theme = theme === 'dark' ? 'light' : 'dark';
    body.classList.toggle('light-theme', theme === 'light');
    icon.className = `fas ${theme === 'light' ? 'fa-moon' : 'fa-sun'}`;
    localStorage.setItem('theme', theme);
}

function toggleMenu() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('active');
}

function analyzeFiles() {
    const resultsSection = document.getElementById('resultsSection');
    const uploadSection = document.getElementById('uploadSection');
    const loading = document.getElementById('loading');
    
    loading.style.display = 'block';
    
    // Замена setTimeout с функцией вместо стрелочной функции
    const timer = window.setTimeout(showResults, 1500);
    
    function showResults() {
        window.clearTimeout(timer);
        uploadSection.style.display = 'none';
        resultsSection.style.display = 'block';
        window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
    }
}

function exportResults() {
    const table = document.querySelector('.result-table');
    const csv = tableToCSV(table);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'analysis_results.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function tableToCSV(table) {
    const rows = [];
    const headers = Array.from(table.querySelectorAll('th')).map(th => th.textContent.trim());
    rows.push(headers.join(','));
    
    table.querySelectorAll('tbody tr').forEach(tr => {
        const cols = Array.from(tr.querySelectorAll('td')).map(td => td.textContent.trim());
        rows.push(cols.join(','));
    });
    
    return rows.join('\n');
}

// Дропзона анимация
const dropzone = document.getElementById('dropzone');
dropzone.ondragover = (e) => {
    e.preventDefault();
    dropzone.style.borderColor = '#64ffda';
};
dropzone.ondragleave = () => {
    dropzone.style.borderColor = getComputedStyle(dropzone).borderColor;
};