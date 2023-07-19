#%%
import json
import pandas as pd
from venn import venn

all_files = ["terraform/alicloud/bucket.tf",
"terraform/alicloud/provider.tf",
"terraform/alicloud/rds.tf",
"terraform/alicloud/trail.tf",
"terraform/aws/consts.tf",
"terraform/aws/db-app.tf",
"terraform/aws/ec2.tf",
"terraform/aws/ecr.tf",
"terraform/aws/eks.tf",
"terraform/aws/elb.tf",
"terraform/aws/es.tf",
"terraform/aws/iam.tf",
"terraform/aws/kms.tf",
"terraform/aws/lambda.tf",
"terraform/aws/neptune.tf",
"terraform/aws/providers.tf",
"terraform/aws/rds.tf",
"terraform/aws/resources/customer-master.xlsx",
"terraform/aws/resources/Dockerfile",
"terraform/aws/resources/lambda_function_payload.zip",
"terraform/aws/s3.tf",
"terraform/azure/aks.tf",
"terraform/azure/application_gateway.tf",
"terraform/azure/app_service.tf",
"terraform/azure/instance.tf",
"terraform/azure/key_vault.tf",
"terraform/azure/logging.tf",
"terraform/azure/mssql.tf",
"terraform/azure/networking.tf",
"terraform/azure/policies.tf",
"terraform/azure/provider.tf",
"terraform/azure/random.tf",
"terraform/azure/resource_group.tf",
"terraform/azure/roles.tf",
"terraform/azure/security_center.tf",
"terraform/azure/sql.tf",
"terraform/azure/storage.tf",
"terraform/azure/variables.tf",
"terraform/gcp/big_data.tf",
"terraform/gcp/gcs.tf",
"terraform/gcp/gke.tf",
"terraform/gcp/instances.tf",
"terraform/gcp/networks.tf",
"terraform/gcp/provider.tf",
"terraform/gcp/README.md",
"terraform/gcp/variables.tf",
"terraform/oracle/bucket.tf",
"terraform/oracle/compartment.tf",
"terraform/oracle/data.tf",
"terraform/oracle/provider.tf",
"terraform/oracle/variables.tf"]

output_files = ["scan_results/scan_terraform_checkov_output/results_json.json",
                 "scan_results/scan_terraform_semgrep_output/semgrep_results.json",
                 "scan_results/scan_terraform_terrascan_output/scan-result.json",
                 "scan_results/scan_terraform_tfsec_output/tfsec_results.json"]

# pd.set_option('display.max_rows', None)
# pd.set_option('display.max_columns', None)
# pd.set_option('display.width', None)
# pd.set_option('display.max_colwidth', None)
pd.reset_option("all")

json_data = []

for file in output_files:
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

all_files = pd.DataFrame(all_files, columns=["file"])

print("Number of found vulnerabilites over all scans")
aggregated_df = pd.concat([checkov_tf_fc_files, semgrep_fc_files, terrascan_vio_files, tfsec_fc_files])
aggregated_vuln = pd.DataFrame(aggregated_df["file"].value_counts())
display(aggregated_vuln)
display(pd.DataFrame(aggregated_df["file"].value_counts()).sum())
display(aggregated_df["file"].value_counts().plot(x=aggregated_df["file"], y=aggregated_df["file"].value_counts, kind="bar", xlabel="File", ylabel="Number of found vulnerabilites over all scans", figsize=(6.5, 6.5), width=0.85))

print("------------------------ venn diagram ------------------------")
venn({
    "checkov": set(checkov_tf_fc_files["file"].to_list()),
    "semgrep": set(semgrep_fc_files["file"].to_list()),
    "terrascan": set(terrascan_vio_files["file"].to_list()),
    "tfsec": set(tfsec_fc_files["file"].to_list())},
    fmt="{size}",
    cmap="plasma")

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