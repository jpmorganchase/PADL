from flask import Flask, request
import json
app = Flask(__name__)

@app.route('/store', methods=['POST'])
def store():
    print('in')
    filename = request.args.get('filename')
    proof = request.args.get('proof')
    print(proof)
    f = open(filename, 'w')
    json.dump(proof, f)
    return "proof saved"

@app.route('/store_long', methods=['POST'])
def store_long():
    data = request.get_json()
    filename = data['filename']
    proof = data['proof']
    f = open(filename, 'w')
    json.dump(proof, f)
    return "proof saved"

@app.route('/retrieve', methods=['GET','POST'])
def download():
    filename = request.args.get('filename')
    f = open(filename, 'r')
    return json.load(f)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
