document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scan-form');
    form.addEventListener('submit', function(event) {
        event.preventDefault();
        document.getElementById('tasks').style.display = 'none';
        document.getElementById('message').innerText = 'Comenzando el escaneo. Esto suele tardar de 2 a 10 minutos.';
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
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = formatResults(data);
        })
        .catch(error => console.error('Error:', error));
    });

    function formatResults(data) {
        let html = '<h2>Resultados del Escaneo</h2>';
        
        // Mensaje si no se encontraron vulnerabilidades en los puertos escaneados
        if (!data.scan_vulnerabilities_found) {
            html += '<p>No se encontraron vulnerabilidades en los puertos escaneados.</p>';
        } else {
            // Formatear resultados del escaneo de puertos
            html += '<h3>Escaneo de Puertos:</h3>';
            data.scan_result.results.forEach(hostResult => {
                html += `<div class="result-block"><p><strong>Host:</strong> ${hostResult.host}</p>`;
                hostResult.protocols.forEach(protocol => {
                    html += `<p><strong>Protocolo:</strong> ${protocol.protocol}</p>`;
                    protocol.ports.forEach(port => {
                        html += `<div class="port-info"><p><strong>Puerto:</strong> ${port.port}, <strong>Producto:</strong> ${port.product}, <strong>Versión:</strong> ${port.version}</p>`;
                        if (port.vulnerable) {
                            html += `<p class="vulnerable">&nbsp;Puerto Vulnerable!</p>`;
                            // html += `<div class="vulnerability-details"><p><strong>Título:</strong> ${port.vul_data.title}</p>`;
                            // tml += `<p><strong>CVSS Score:</strong> ${port.vul_data.cvss_score}</p>`;
                            // html += `<p><strong>Descripción:</strong> ${port.vul_data.description}</p>`;
                            // html += `<p><strong>Referencias:</strong> ${port.vul_data.references}</p></div>`;
                        } else {
                            html += `<p>&nbsp;Puerto No Vulnerable</p>`;
                        }
                        html += `</div>`; // Close port-info div
                    });
                });
                html += `</div>`; // Close result-block div
            });
        }

        // Mensaje si no se logró realizar la fuerza bruta
        if (!data.brute_force_successful) {
            html += '<p>Intentamos realizar fuerza bruta pero no lo logramos debido a que su sistema es seguro.</p>';
        } else {
            // Formatear resultados de la fuerza bruta
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
                html += `</p></div>`; // Close result-block div
            });
        }

        return html;
    }
});