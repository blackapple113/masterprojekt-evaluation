import pandas as pd

tfsec_pandas = pd.read_json(path_or_buf="scan_results/scan_terraform_tfsec_output/tfsec_results.json")
normalize = pd.json_normalize()

print(tfsec_pandas)
