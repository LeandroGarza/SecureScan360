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
            resultsDiv.innerHTML = JSON.stringify(data, null, 2);
        })
        .catch(error => console.error('Error:', error));
    });
});
