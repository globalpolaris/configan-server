from flask import Flask, request, flash, redirect
from flask_cors import CORS
import os
from processConfigFile.process import process

UPLOAD_FOLDER = './config_files'
ALLOWED_EXTENSIONS = {'txt'}
app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/convert-to-txt", methods=['POST'])
def convert_to_txt():
    if request.method == 'POST':
        return {
            "message": "Convert To TXT"
        }


@app.route("/process-config-file", methods=['POST'])
def process_config_file():
    if request.method == 'POST':
        destination = request.form['destination']
        timezone = request.form['timezone']
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = file.filename.replace(' ', '_')
            file.save(os.path.join(
                app.config['UPLOAD_FOLDER'], filename))
            # if destination == 'fortigate':
            data = process(destination, timezone, filename)
            message = f"File uploaded: {filename}"
            return data

        return {
            "message": "Error"
        }
