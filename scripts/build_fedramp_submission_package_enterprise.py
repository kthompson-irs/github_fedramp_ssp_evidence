import shutil, json, argparse, os
from pathlib import Path

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input")
    p.add_argument("--spreadsheets")
    p.add_argument("--output")
    args = p.parse_args()

    out = Path(args.output)
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)

    # copy evidence
    shutil.copytree(args.input, out/"Evidence", dirs_exist_ok=True)
    shutil.copytree(args.spreadsheets, out/"Spreadsheets", dirs_exist_ok=True)

    # minimal SSP + OSCAL
    with open(out/"SSP.md","w") as f:
        f.write("SA-04(10) Evidence Package")

    with open(out/"OSCAL.json","w") as f:
        json.dump({"control":"SA-04(10)"},f,indent=2)

if __name__ == "__main__":
    main()
