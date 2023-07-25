import json
import boto3
from output import output_srx, output_fgt
from pathlib import Path
import uuid

s3 = boto3.client('s3')
bucket_name = "configan-file"


def generate_presigned_download(object_name):
    try:
        print("Trying generate_presigned_download()...")
        response = s3.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_name}, ExpiresIn=300)
        return response
    except Exception as e:
        logging.error(e)
        return None


def lambda_handler(event, context):

    # filename = Path(event["data"]["filename"]).stem
    filename = uuid.uuid4()
    data = event["data"]
    print(data)
    # print(type(data))
    # print(filename)
    # TODO implement
    try:
        print("Awal: ", event["data"])
        # s3.download_file(bucket_name, f"final/{filename}.json", f"/tmp/temp-{filename}.json")
        # with open(f"/tmp/temp-{filename}.json") as json_file:
        # data_dict = json.loads(data)
        print("event:", event)
        if event["destinationDevice"].lower() == "junipersrx":
            output_srx(f"/tmp/{filename}.txt", data)
        elif event["destinationDevice"].lower() == "fortigate":
            output_fgt(f"/tmp/{filename}.txt", data)
        s3.upload_file(f"/tmp/{filename}.txt", bucket_name, f"{filename}.txt")
        response = generate_presigned_download(f"{filename}.txt")
        return {
            'statusCode': 200,
            'body': response
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': e
        }
