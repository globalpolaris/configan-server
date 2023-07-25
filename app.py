from flask import Flask, request

app = Flask(__name__)


@app.route("/convert-to-txt", methods=['POST'])
def convert_to_txt():
    if request.method == 'POST':
        return {
            "message": "Convert To TXT"
        }


@app.route("/process-config-file", methods=['POST'])
def process_config_file():
    if request.method == 'POST':
        return {
            "message": "Convert To TXT"
        }
