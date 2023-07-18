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
print("------------------------ checkov ------------------------")
# select terraform failed checks
checkov_tf_fc = pd.json_normalize(checkov_df["results.failed_checks"].iloc[0])
# select secrets failed checks
checkov_secrets_fc = pd.json_normalize(checkov_df["results.failed_checks"].iloc[2])

checkov_tf_fc_clean_filename = checkov_tf_fc["file_path"].str.replace("/terraform", "terraform")
checkov_secrets_fc_clean_filename = checkov_secrets_fc["file_path"].str.replace("/terraform", "terraform")

# query file name and affected line number
checkov_tf_fc_files = checkov_tf_fc[["file_line_range"]].join(checkov_tf_fc_clean_filename).rename(columns={"file_path": "file"})
checkov_tf_fc_unique_files = checkov_tf_fc_files["file"].unique()
checkov_secrets_fc_files = checkov_secrets_fc[["file_line_range"]].join(checkov_secrets_fc_clean_filename).rename(columns={"file_path": "file"})

display(checkov_tf_fc_files)
# display(checkov_secrets_fc_files)
# display(checkov_tf_fc_unique_files)

#### semgrep ####
print("------------------------ semgrep ------------------------")
semgrep_fc = pd.json_normalize(semgrep_df["results"].iloc[0])

semgrep_fc_files = semgrep_fc[["path", "start.col", "start.line", "end.col", "end.line"]].rename(columns={"path": "file"})
semgrep_fc_unique_files = semgrep_fc_files["file"].unique()

display(semgrep_fc_files)
# display(semgrep_fc_unique_files)

#### terrascan ####
print("------------------------ terrascan ------------------------")
terrascan_vio = pd.json_normalize(terrascan_df["results.violations"].iloc[0])

terrascan_vio_files = terrascan_vio[["file", "line"]]
terrascan_vio_unique_files = terrascan_vio_files["file"].unique()

display(terrascan_vio_files)
# display(terrascan_vio_unique_files)

#### tfsec ####
print("------------------------ tfsec ------------------------")
tfsec_fc = pd.json_normalize(tfsec_df["results"].iloc[0])

tfsec_clean_filename = tfsec_fc["location.filename"].str.replace("/terraform/terraform", "terraform")

tfsec_fc_files = tfsec_fc[["location.start_line", "location.end_line"]].join(tfsec_clean_filename).rename(columns={"location.filename": "file"})
tfsec_fc_unique_files = tfsec_fc_files["file"].unique()

display(tfsec_fc_files)
# display(tfsec_fc_unique_files)

#### evaluation ####
print("------------------------ file joint ------------------------")

print("Number of found vulnerabilites over all scans")
aggregated_df = pd.concat([checkov_tf_fc_files, semgrep_fc_files, terrascan_vio_files, tfsec_fc_files])
display(pd.DataFrame(aggregated_df["file"].value_counts()))
display(pd.DataFrame(aggregated_df["file"].value_counts()).sum())
display(aggregated_df["file"].value_counts().plot(x=aggregated_df["file"], y=aggregated_df["file"].value_counts, kind="bar", xlabel="File", ylabel="Number of found vulnerabilites over all scans"))


# %%

import requests

pd.reset_option("all")

request_json = requests.get("https://semgrep.dev/api/registry/rules?definition=1&test_cases=1").json()

# display(request.json())

# semgrep_rules = json.load(request.text)

# pd.set_option('display.max_rows', None)
# pd.set_option('display.max_columns', None)
# pd.set_option('display.width', None)
# pd.set_option('display.max_colwidth', None)

# with open("./rules.json", encoding='utf8') as f:
#     semgrep_rules = json.load(f)

semgrep_rules = request_json

semgrep_rules = pd.json_normalize(semgrep_rules)

semgrep_community_rules = semgrep_rules.loc[semgrep_rules['meta.rule.origin'] == "community"]

semgrep_tf_community_rules = semgrep_community_rules[semgrep_community_rules.path.str.contains(r"terraform.*", na=False)]


for i, uri in enumerate(semgrep_tf_community_rules["source_uri"]):
    if i == 0:
        uri = str(uri).replace("github.com","raw.githubusercontent.com").replace("/blob/", "/")
        print(uri)
        print(requests.get(uri).text)

# display(semgrep_tf_community_rules["source_uri"])
# %%


https://raw.githubusercontent.com/returntocorp/semgrep-rules/blob/release/terraform/azure/best-practice/azure-keyvault-recovery-enabled.yaml
https://raw.githubusercontent.com/returntocorp/semgrep-rules/release/terraform/azure/best-practice/azure-keyvault-recovery-enabled.yaml
