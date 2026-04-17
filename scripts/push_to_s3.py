#!/usr/bin/env python3
import boto3, datetime

BUCKET = "ps04-evidence-bucket"

def main():
    s3 = boto3.client("s3")

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    key = f"ps04/{timestamp}.json"

    with open("ps04_report.json", "rb") as f:
        s3.put_object(
            Bucket=BUCKET,
            Key=key,
            Body=f,
        )

    print(f"Uploaded to s3://{BUCKET}/{key}")

if __name__ == "__main__":
    main()
