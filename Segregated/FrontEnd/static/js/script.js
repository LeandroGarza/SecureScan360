document.addEventListener('DOMContentLoaded', function() {
    const targetInput = document.getElementById('target');
    const loadingMessage = document.getElementById('loading-message');
    const tasksSection = document.getElementById('tasks');
    const resultsDiv = document.getElementById('results');
    const messageDiv = document.getElementById('message');

    // Botones para seleccionar la prueba
    const buttons = {
        sql: document.getElementById('sql-button'),
        xss: document.getElementById('xss-button'),
        portScan: document.getElementById('port-scan-button'),
        bruteForce: document.getElementById('brute-force-button')
    };

    function runScan(testType) {
        loadingMessage.style.display = 'block';
        tasksSection.style.display = 'none';
        resultsDiv.style.display = 'none';
        messageDiv.style.display = 'none';

        const target = targetInput.value;

        fetch('http://127.0.0.1:5000/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target, test_type: testType })
        })
        .then(response => {
            if (response.status === 403) {
                throw new Error(`[+] Access to ${target} was blocked with a 403 (Forbidden) code.`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                messageDiv.innerText = data.error;
                messageDiv.style.display = 'block';
                messageDiv.style.color = 'red';
            } else {
                resultsDiv.innerHTML = formatResults(data, testType);
                resultsDiv.style.display = 'block';
            }
            loadingMessage.style.display = 'none';
        })
        .catch(error => {
            console.error('Error:', error);
            loadingMessage.style.display = 'none';
            messageDiv.innerText = 'Error al realizar la solicitud.';
            messageDiv.style.display = 'block';
            messageDiv.style.color = 'red';
        });
    }

    // Event listeners para cada botón de prueba
    buttons.sql.addEventListener('click', () => runScan('sql_injection'));
    buttons.xss.addEventListener('click', () => runScan('xss'));
    buttons.portScan.addEventListener('click', () => runScan('port_scan'));
    buttons.bruteForce.addEventListener('click', () => runScan('brute_force'));

    function formatResults(data, testType) {
        let html = `<h2>Resultados de la Prueba: ${testType.replace('_', ' ').toUpperCase()}</h2>`;
        
        switch (testType) {
            case 'port_scan':
                // Generar HTML específico para Escaneo de Puertos
                break;
            case 'brute_force':
                // Generar HTML específico para Fuerza Bruta
                break;
            case 'sql_injection':
                // Generar HTML específico para SQL Injection
                break;
            case 'xss':
                // Generar HTML específico para XSS
                break;
        }
        
        return html;
    }
});
