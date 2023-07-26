import json
from .output import output_srx, output_fgt
from pathlib import Path
import uuid


def convert(destination, data):
    id = uuid.uuid4()
    print(data)

    # TODO implement
    try:
        if destination.lower() == "junipersrx":
            dst_file = str(
                Path(f"./config_files/result/fgt_{id}.txt").resolve())
            output_srx(dst_file, data)
        elif destination.lower() == "fortigate":
            dst_file = str(
                Path(f"./config_files/result/srx_{id}.txt").resolve())
            output_fgt(dst_file, data)
        return {
            'statusCode': 200,
            'body': "Success"
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': e
        }
