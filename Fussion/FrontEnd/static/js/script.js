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
            displayResults(data);
        })
        .catch(error => console.error('Error:', error));
    });
});

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = ''; // Clear previous results

    if (data.vulnerabilities_found) {
        resultsDiv.innerHTML += '<h2>Vulnerabilities Found</h2>';
    } else {
        resultsDiv.innerHTML += '<h2>No Vulnerabilities Found</h2>';
    }

    data.results.forEach(host => {
        resultsDiv.innerHTML += `<h3>Host: ${host.host}</h3>`;
        host.protocols.forEach(proto => {
            resultsDiv.innerHTML += `<h4>Protocol: ${proto.protocol}</h4>`;
            proto.ports.forEach(port => {
                resultsDiv.innerHTML += `<p>Port: ${port.port}</p>`;
                resultsDiv.innerHTML += `<p>Product: ${port.product}</p>`;
                resultsDiv.innerHTML += `<p>Version: ${port.version}</p>`;
                if (port.vulnerable) {
                    resultsDiv.innerHTML += `<p style="color:red;">Vulnerable: Yes</p>`;
                    resultsDiv.innerHTML += `<p>Title: ${port.vul_data.title}</p>`;
                    resultsDiv.innerHTML += `<p>CVSS Score: ${port.vul_data.cvss_score}</p>`;
                    resultsDiv.innerHTML += `<p>Description: ${port.vul_data.description}</p>`;
                    resultsDiv.innerHTML += `<p>References: ${port.vul_data.references}</p>`;
                } else {
                    resultsDiv.innerHTML += `<p style="color:green;">Vulnerable: No</p>`;
                }
                resultsDiv.innerHTML += '<hr>';
            });
        });
    });
}
