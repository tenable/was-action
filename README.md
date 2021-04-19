# was-action
Tenable's WAS action

This action can be used to trigger a WAS scan. The scan needs to be configured in the Tenable.io WAS dashboard. The scan name and the folder name 
need to provided as input for the action to launch the scan. The action does not modify the scan configuration The `wait_for_results` optional input can be used to make the action wait for the results of the scan.


Note: <b>It is important to modify `OVERALL SCAN MAX TIME` on the Tenable.io dashboard as per your organisation's requirements as the `wait_for_results` input will make the action wait for the entire duration of the scan.</b>

### Example workflow

```yaml
name: Test WAS workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Runs the WAS scan
        uses: tenable/was-action@v0
        id: was
        with:
          scan_name: test_scan
          wait_for_results: "true"
        env:
          ACCESS_KEY: ${{ secrets.ACCESS_KEY }}
          SECRET_KEY: ${{ secrets.SECRET_KEY }}
```

### Inputs

| Input                                             | Description                                        |
|------------------------------------------------------|-----------------------------------------------|
| `scan_name`  | Scan name mentioned on T.io  |
| `folder_name`   | Folder name in which the scan resides |
| `wait_for_results` _(optional)_   | Boolean to specify if action should wait for results |
| `check_thresholds` _(optional)_  | If the action should check results against the set thresholds |
| `low_vulns_threshold` _(optional)_  | Low severity findings threshold to be checked based on the WAS scan results |
| `medium_vulns_threshold` _(optional)_  | Medium severity findings threshold to be checked based on the WAS scan results |
| `high_vulns_threshold` _(optional)_  | High severity findings threshold to be checked based on the WAS scan results |
| `critical_vulns_threshold` _(optional)_  | High severity findings threshold to be checked based on the WAS scan results |

### Outputs

| Output                                             | Description                                        |
|------------------------------------------------------|-----------------------------------------------|
| `number_of_low_severity_findings`  | Number of low severity findings found in the scan |
| `number_of_medium_severity_findings`  | Number of medium severity findings found in the scan |
| `number_of_high_severity_findings`  | Number of high severity findings found in the scan|
| `number_of_critical_severity_findings`  | Number of critical severity findings found in the scan|

### Providing secrets
The Tenable.io access key and secret key need to be set in your repository secrets and provided the following way to the action
```yaml
    env:
        ACCESS_KEY: ${{ secrets.ACCESS_KEY }}
        SECRET_KEY: ${{ secrets.SECRET_KEY }}
```
The action uses these secrets to push the image to the tenable registry and to get the scan results. The access and secret key can be 
generated by accessing `Tenable.io -> Settings -> My Account -> API Keys -> Generate`. It is important that these keys should not be shared publicly.

### Using outputs

The outputs can be accessed using the following way

```yaml
    - name: Gets the number of low severity findings
    run: echo "Number of low severity findings is ${{ steps.was.outputs.number_of_low_severity_findings }}"
    - name: Gets the number of medium severity findings
    run: echo "Number of medium severity findings is ${{ steps.was.outputs.number_of_medium_severity_findings }}"
    - name: Gets the number of high severity findings
    run: echo "Number of high severity is ${{ steps.was.outputs.number_of_high_severity_findings }}"
```

### Lincese
The project is licensed under the MIT license.
