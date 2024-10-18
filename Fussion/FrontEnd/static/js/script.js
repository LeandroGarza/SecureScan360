document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scan-form');
    form.addEventListener('submit', function(event) {
        event.preventDefault();

        const loadingMessage = document.getElementById('loading-message');
        const tasksSection = document.getElementById('tasks');
        const resultsDiv = document.getElementById('results');
        const messageDiv = document.getElementById('message');
        const realTimeOutput = document.getElementById('real-time-output');

        loadingMessage.style.display = 'block';
        tasksSection.style.display = 'none';
        resultsDiv.style.display = 'none';
        messageDiv.style.display = 'none';

        const target = document.getElementById('target').value;

        fetch('http://127.0.0.1:5000/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
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
                resultsDiv.innerHTML = formatResults(data);
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

        const eventSource = new EventSource('http://127.0.0.1:5000/events');
        eventSource.onmessage = function(event) {
            realTimeOutput.innerHTML += `<p>${event.data}</p>`;
        };
    });

    function formatResults(data) {

        let html = '<h2>Resultados del Escaneo</h2>';

        html += '<h3>Prueba de Escaneo de Puertos:</h3>';
        if (!data.scan_vulnerabilities_found) {
            html += '<p>No se encontraron vulnerabilidades en los puertos escaneados.</p>';
        } else {
            data.scan_result.results.forEach(hostResult => {
                html += `<div class="result-block"><p><strong>Host:</strong> ${hostResult.host}</p>`;
                hostResult.protocols.forEach(protocol => {
                    html += `<p><strong>Protocolo:</strong> ${protocol.protocol}</p>`;
                    protocol.ports.forEach(port => {
                        html += `<div class="port-info"><p><strong>Puerto:</strong> ${port.port}, <strong>Producto:</strong> ${port.product}, <strong>Versión:</strong> ${port.version}</p>`;
                        if (port.vulnerable) {
                            html += `<p class="vulnerable">&nbsp;Puerto Vulnerable!</p>`;
                        } else {
                            html += `<p>&nbsp;Puerto No Vulnerable</p>`;
                        }
                        html += `</div>`;
                    });
                });
                html += `</div>`;
            });
        }

        html += '<h3>Prueba de Fuerza Bruta:</h3>';
        if (!data.brute_force_successful) {
            html += '<p>Intentamos realizar fuerza bruta pero no lo logramos debido a que su sistema es seguro.</p>';
        } else {
            data.brute_force_result.forEach(result => {
                html += `<div class="result-block"><p><strong>Usuario:</strong> ${result.username}, <strong>Contraseña:</strong> ${result.password}, `;
                if (result.status === 'success') {
                    html += `<span class="status-success">Estado: Éxito</span> en ${result.service}`;
                } else if (result.status === 'failure') {
                    html += `<span class="status-failure">Estado: Contraseña Incorrecta</span>`;
                } else if (result.status === 'ssh_exception') {
                    html += `<span class="status-error">Estado: Error SSH</span><p>Error: ${result.error}</p>`;
                } else if (result.status === 'connection_failed') {
                    html += `<span class="status-error">Estado: Conexión Fallida</span><p>Error: ${result.error}</p>`;
                } else {
                    html += `<span class="status-error">Estado: Error Desconocido</span><p>Error: ${result.error || 'Desconocido'}</p>`;
                }
                html += `</p></div>`;
            });
        }

        html += '<h3>Prueba de SQL Injection:</h3>';
        if (!data.sql_vulnerabilities_found) {
            html += '<p>No se encontraron vulnerabilidades de sql en los puertos escaneados.</p>';
        } else {
            data.sql_injection_results.forEach(result => {
                html += `<div class="result-block"><p><strong>URL Vulnerable:</strong> ${result.url}</p>`;
                html += `<p><strong>Payload:</strong> ${result.payloads.join(', ')}</p>`;
                
                if (result.payloads.length > 0) {
                    html += `<p class="vulnerable">¡Vulnerable a SQL Injection!</p>`;
                } else {
                    html += `<p>No vulnerable a SQL Injection</p>`;
                }
                html += `</div>`;
            });
        }
        
        html += '<h3>Prueba de XSS:</h3>';
        if (data.xss_results && data.xss_results.length > 0) {
            data.xss_results.forEach(result => {
                html += `<div class="result-block"><p><strong>URL:</strong> ${result.url}</p>`;
                if (result.vulnerable) {
                    html += `<p class="vulnerable">¡Vulnerable a XSS!</p>`;
                } else {
                    html += `<p>No vulnerable a XSS</p>`;
                }
                html += `</div>`;
            });
        }

        html += '<p>¡Felicitaciones! El escaneo de puertos, la prueba de fuerza bruta, el sql injection y xss han finalizado con éxito.</p>';
        return html;
    }
});
