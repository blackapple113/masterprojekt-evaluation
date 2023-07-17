#%%
import json
import pandas as pd

outputs_files = ["scan_results/scan_terraform_checkov_output/results_json.json",
                 "scan_results/scan_terraform_semgrep_output/semgrep_results.json",
                 "scan_results/scan_terraform_terrascan_output/scan-result.json",
                 "scan_results/scan_terraform_tfsec_output/tfsec_results.json"]

# pd.set_option('display.max_rows', None)
# pd.set_option('display.max_columns', None)
# pd.set_option('display.width', None)
# pd.set_option('display.max_colwidth', None)
pd.reset_option("all")

json_data = []

for file in outputs_files:
    with open(file) as f:
        json_data.append(json.load(f))

# checkov
checkov_df = pd.json_normalize(json_data[0])

# semgrep
semgrep_df = pd.json_normalize(json_data[1])

# terrascan
terrascan_df = pd.json_normalize(json_data[2])

# tfsec
tfsec_df = pd.json_normalize(json_data[3])

#### checkov ####
# select terraform failed checks
checkov_tf_fc = pd.json_normalize(checkov_df["results.failed_checks"].iloc[0])
# select secrets failed checks
checkov_secrets_fc = pd.json_normalize(checkov_df["results.failed_checks"].iloc[2])

# query file name and affected line number
checkov_tf_fc_files = checkov_tf_fc[["file_path", "file_line_range"]]
checkov_secrets_fc_files = checkov_secrets_fc[["file_path", "file_line_range"]]

display(checkov_tf_fc_files)
display(checkov_secrets_fc_files)

#### semgrep ####
semgrep_fc = pd.json_normalize(semgrep_df["results"].iloc[0])

semgrep_line_numbers = semgrep_fc[["start.line", "end.line"]]

semgrep_line_numbers_list = []

for i, row in semgrep_line_numbers.iterrows():
    semgrep_line_numbers_list.append([row[0], row[1]])

semgrep_line_numbers_list_series = pd.Series(semgrep_line_numbers_list, name="file_line_range")

semgrep_fc_path = semgrep_fc[["path"]]
semgrep_fc_files = semgrep_fc_path.merge(semgrep_line_numbers_list_series, left_index=True, right_index=True)
display(semgrep_fc_files)


#### terrascan ####


# %%
