document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scan-form');
    form.addEventListener('submit', function(event) {
        event.preventDefault();
        const target = document.getElementById('target').value;
        fetch('http://127.0.0.1:5000/scan', {  // URL correcta
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
        
        // Formatear resultados del escaneo de puertos
        html += '<h3>Escaneo de Puertos:</h3>';
        data.scan_result.results.forEach(hostResult => {
            html += `<p>Host: ${hostResult.host}</p>`;
            hostResult.protocols.forEach(protocol => {
                html += `<p>Protocolo: ${protocol.protocol}</p>`;
                protocol.ports.forEach(port => {
                    html += `<p>Puerto: ${port.port}, Producto: ${port.product}, Versión: ${port.version}</p>`;
                    if (port.vulnerable) {
                        html += `<p style="color: red;">Vulnerable: Sí</p>`;
                        html += `<p>Detalles de la vulnerabilidad:</p>`;
                        html += `<p>Título: ${port.vul_data.title}</p>`;
                        html += `<p>CVSS Score: ${port.vul_data.cvss_score}</p>`;
                        html += `<p>Descripción: ${port.vul_data.description}</p>`;
                        html += `<p>Referencias: ${port.vul_data.references}</p>`;
                    } else {
                        html += `<p>Vulnerable: No</p>`;
                    }
                });
            });
        });

        // fuerza bruta
        html += '<h3>Resultados de la Fuerza Bruta:</h3>';
        data.brute_force_result.forEach(result => {
            html += `<p>Usuario: ${result.username}, Contraseña: ${result.password}, Estado: ${result.status}</p>`;
            if (result.status === 'ssh_exception' || result.status === 'connection_failed') {
                html += `<p>Error: ${result.error}</p>`;
            }
        });

        return html;
    }
});
