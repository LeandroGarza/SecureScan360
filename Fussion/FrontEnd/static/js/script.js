document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scan-form');
    form.addEventListener('submit', function(event) {
        event.preventDefault();

        const loadingMessage = document.getElementById('loading-message');
        const tasksSection = document.getElementById('tasks');
        const resultsDiv = document.getElementById('results');
        
        loadingMessage.style.display = 'block';
        tasksSection.style.display = 'none';
        resultsDiv.style.display = 'none';

        const target = document.getElementById('target').value;
        fetch('http://127.0.0.1:5000/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        })
        .then(response => response.json())
        .then(data => {
            resultsDiv.innerHTML = formatResults(data);
            loadingMessage.style.display = 'none';
            resultsDiv.style.display = 'block';
        })
        .catch(error => {
            console.error('Error:', error);
            loadingMessage.style.display = 'none';
        });
    });

    function formatResults(data) {
        let html = '<h2>Resultados del Escaneo</h2>';
        
        if (!data.scan_vulnerabilities_found) {
            html += '<p>No se encontraron vulnerabilidades en los puertos escaneados.</p>';
        } else {
            html += '<h3>Escaneo de Puertos:</h3>';
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

        if (!data.brute_force_successful) {
            html += '<p>Intentamos realizar fuerza bruta pero no lo logramos debido a que su sistema es seguro.</p>';
        } else {
            html += '<h3>Resultados de la Fuerza Bruta:</h3>';
            data.brute_force_result.forEach(result => {
                html += `<div class="result-block"><p><strong>Usuario:</strong> ${result.username}, <strong>Contraseña:</strong> ${result.password}, `;
                if (result.status === 'success') {
                    html += `<span class="status-success">Estado: Éxito</span>`;
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

        return html;
    }
});
