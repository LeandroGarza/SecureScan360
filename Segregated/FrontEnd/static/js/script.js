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
            console.log('Data recibida del backend:', data);
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
            console.error('Error exacto:', error);
            loadingMessage.style.display = 'none';
            messageDiv.innerText = `Error al realizar la solicitud: ${error.message}`;
            messageDiv.style.display = 'block';
            messageDiv.style.color = 'red';
        });
    }
    
    
    buttons.sql.addEventListener('click', () => runScan('sql_injection'));
    buttons.xss.addEventListener('click', () => runScan('xss'));
    buttons.portScan.addEventListener('click', () => runScan('port_scan'));
    buttons.bruteForce.addEventListener('click', () => runScan('brute_force'));

    function formatResults(data, testType) {

        let html = `<h2>Resultados de la Prueba: ${testType.replace('_', ' ').toUpperCase()}</h2>`;

        switch (testType) {
            case 'port_scan':
                html += '<h3>Prueba de Escaneo de Puertos:</h3>';
                if (!data.scan_vulnerabilities_found) {
                    html += '<p>No se encontraron vulnerabilidades en los puertos escaneados.</p>';
                } else {
                    data.scan_result.results.forEach(hostResult => {
                        html += `<div class="result-block"><p><strong>Host:</strong> ${hostResult.host}</p>`;
                        hostResult.protocols.forEach(protocol => {
                            html += `<p><strong>Protocolo:</strong> ${protocol.protocol}</p>`;
                            protocol.ports.forEach(port => {
                                if (port.product || port.version) {
                                    html += `<div class="port-info"><p><strong>Puerto:</strong> ${port.port}, <strong>Producto:</strong> ${port.product}, <strong>Versión:</strong> ${port.version}</p>`;
                                    if (port.vulnerable) {
                                        html += `<p class="vulnerable">&nbsp;Puerto Vulnerable!</p>`;
                                    } else {
                                        html += `<p>&nbsp;Puerto No Vulnerable</p>`;
                                    }
                                html += `</div>`;
                                }
                            });
                        });
                        html += `</div>`;
                    });
                }
                break;
        
            case 'brute_force':
                html += '<h3>Prueba de Fuerza Bruta:</h3>';
                if (!data.brute_force_successful) {
                    html += '<p>Intentamos realizar fuerza bruta pero no lo logramos debido a que su sistema es seguro.</p>';
                } else {
                    html += `<h4>🔍 Credenciales encontradas durante la prueba de fuerza bruta:</h4>`;
                    data.brute_force_result.forEach(result => {
                        html += `<div class="result-block"><p><strong>🔑 Usuario:</strong> "${result.username}" <strong>🔒 Contraseña:</strong> "${result.password}" `;
                        if (result.status === 'success') {
                            html += `en servicio ${result.service} que corre en puerto ${result.port}. `;
                        } 
                        /*else if (result.status === 'failure') {
                            html += `<span class="status-failure">Estado: Contraseña Incorrecta</span>`;
                        } else if (result.status === 'ssh_exception') {
                            html += `<span class="status-error">Estado: Error SSH</span><p>Error: ${result.error}</p>`;
                        } else if (result.status === 'connection_failed') {
                            html += `<span class="status-error">Estado: Conexión Fallida</span><p>Error: ${result.error}</p>`;
                        } else {
                            html += `<span class="status-error">Estado: Error Desconocido</span><p>Error: ${result.error || 'Desconocido'}</p>`;
                        }*/
                        html += `</p></div>`;
                    });
                }
                break;
            
            case 'sql_injection':

                html += '<h3>Prueba de SQL Injection:</h3>';

                if (data.status_messages) {
                    html += '<h4>URLs relacionadas a escanear:</h4>';
                    data.status_messages.forEach(message => {
                        html += `<p>${message}</p>`;
                    });
                }

                if (!data.sql_vulnerabilities_found && !data.columns_detected_found && !data.admin_password_found && !data.database_version_found) {
                    html += '<p>No se encontraron vulnerabilidades de sql en los puertos escaneados.</p>';
                } else {
                    if (data.sql_vulnerabilities_found) {
                        html += '<h4>Vulnerabilidades Encontradas:</h4>';
                        data.sql_injection_results.forEach(result => {
                            html += `<div class="result-block"><p><strong>URL Vulnerable:</strong> ${result.url}</p>`;
                            html += `<p><strong>Payload:</strong> ${result.payloads.join(', ')}</p>`;
                            html += `<p class="vulnerable">¡Vulnerable a SQL Injection!</p>`;
                            html += `</div>`;
                        });
                    }
        
                    if (data.columns_detected_found) {
                        html += '<h4>¡Pudimos detectar el numero de columnas de su base de datos!</h4>';
                        data.column_detection_results.forEach(result => {
                            html += `<div class="result-block"><p><strong>URL relacionada:</strong> ${result.url}</p>`;
                            html += `<p><strong>Número de columnas detectadas:</strong> ${result.columns_detected}</p>`;
                            html += `</div>`;
                        });
                    }

                    if (data.admin_password_found) {
                        html += '<h4>Contraseña de Administrador Encontrada:</h4>';
                        data.admin_password_results.forEach(result => {
                            html += `<div class="result-block"><p><strong>URL:</strong> ${result.url}</p>`;
                            html += `<p><strong>Contraseña del Administrador:</strong> ${result.admin_password}</p>`;
                            html += `</div>`;
                        });
                    }

                    if (data.database_version_found) {
                        html += '<h4> Se encontro la versión de la Base de Datos:</h4>';
                        data.database_version_results.forEach(result => {
                            html += `<div class="result-block"><p><strong>URL:</strong> ${result.url}</p>`;
                            html += `<p><strong>Versión de la Base de Datos:</strong> ${result.database_version}</p></div>`;
                        });
                    }
                }
                break;

            case 'xss':
                html += '<h3>Prueba de XSS:</h3>';
                if (!data.xss_vulnerabilities_found && !data.xss_form_vulnerabilities_found) {
                    html += '<p>No se encontraron vulnerabilidades de XSS en los puertos escaneados.</p>';
                } else {
                    if (data.xss_vulnerabilities_found) {
                        html += '<h4>Vulnerabilidades XSS Encontradas en URLs:</h4>';
                        data.xss_results.forEach(result => {
                            html += `<div class="result-block"><p><strong>URL Vulnerable:</strong> ${result.url}</p>`;
                            html += `<p><strong>Payload Usado:</strong> ${result.xss_payload}</p>`;
                            html += `<p class="vulnerable">¡Vulnerable a XSS!</p>`;
                            html += `</div>`;
                        });
                    }

                    if (data.xss_form_vulnerabilities_found) {
                        html += '<h4>Vulnerabilidades XSS Encontradas en Formularios:</h4>';
                        data.xss_form_results.forEach(result => {
                            html += `<div class="result-block"><p><strong>URL:</strong> ${result.url}</p>`;
                            html += `<p><strong>Payload en Formulario Usado:</strong> ${result.xss_form_payload}</p>`;
                            html += `<p class="vulnerable">¡Formulario Vulnerable a XSS!</p>`;
                            html += `</div>`;
                        });
                    }
                }
                break;
        }

        html += '<p>¡Felicitaciones! El escaneo de puertos, la prueba de fuerza bruta, el sql injection y xss han finalizado con éxito.</p>';
        return html;
    }
  
});
