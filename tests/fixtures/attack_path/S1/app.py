from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post("/import")
def import_settings():
    data = yaml.full_load(request.files["settings"].read())   # user-uploaded YAML
    return {"keys": sorted(data)}
