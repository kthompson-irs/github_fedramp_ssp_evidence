# =========================
# Python Script: enterprise_backup.py
# =========================

import os
import requests
import subprocess
import hashlib
import tarfile
import boto3
from datetime import datetime

GH_TOKEN = os.getenv("GH_TOKEN")
ORG = os.getenv("ORG_NAME")
BUCKET = os.getenv("S3_BUCKET")
REGION = os.getenv("AWS_REGION")
KMS_KEY = os.getenv("KMS_KEY_ID")

TIMESTAMP = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

headers = {
    "Authorization": f"token {GH_TOKEN}",
    "Accept": "application/vnd.github+json"
}


def get_repositories():
    repos = []
    page = 1

    while True:
        url = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&page={page}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()
        if not data:
            break

        repos.extend([repo["clone_url"] for repo in data])
        page += 1

    return repos


def run(cmd):
    subprocess.run(cmd, shell=True, check=True)


def backup_repo(repo_url):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    backup_dir = f"{repo_name}-{TIMESTAMP}"
    archive = f"{backup_dir}.tar.gz"
    hash_file = f"{archive}.sha256"

    print(f"[+] Backing up {repo_name}")

    run(f"git clone --mirror {repo_url} {backup_dir}.git")

    with tarfile.open(archive, "w:gz") as tar:
        tar.add(f"{backup_dir}.git")

    sha256 = hashlib.sha256()
    with open(archive, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    digest = sha256.hexdigest()

    with open(hash_file, "w") as f:
        f.write(f"{digest}  {archive}\n")

    upload_to_s3(repo_name, archive, hash_file)


def upload_to_s3(repo_name, archive, hash_file):
    s3 = boto3.client("s3", region_name=REGION)

    key_prefix = f"enterprise-backups/{ORG}/{repo_name}/{TIMESTAMP}/"

    for file in [archive, hash_file]:
        s3.upload_file(
            file,
            BUCKET,
            key_prefix + file,
            ExtraArgs={
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": KMS_KEY
            }
        )


def main():
    repos = get_repositories()
    print(f"[+] Found {len(repos)} repositories")

    for repo in repos:
        try:
            backup_repo(repo)
        except Exception as e:
            print(f"[!] Failed to back up {repo}: {e}")

    print("[+] Enterprise backup complete")


if __name__ == "__main__":
    main()
