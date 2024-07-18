from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')
    result = subprocess.run(['python', '../BackEnd/main.py', target], capture_output=True, text=True)
    return jsonify(result.stdout)

if __name__ == '__main__':
    app.run(debug=True)
