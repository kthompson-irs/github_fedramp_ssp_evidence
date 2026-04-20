from openpyxl import Workbook
from datetime import datetime, timedelta
import json, argparse, os

def build(name):
    wb = Workbook()
    ws = wb.active
    ws.title = "30-Day Log"
    ws.append(["Date","Count"])
    today = datetime.utcnow().date()
    for i in range(30):
        ws.append([today - timedelta(days=i), ""])
    wb.save(name)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument("--output")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    build(f"{args.output}/dependabot_30_day_log.xlsx")
    build(f"{args.output}/security_30_day_log.xlsx")
    build(f"{args.output}/codeql_30_day_log.xlsx")

if __name__ == "__main__":
    main()
