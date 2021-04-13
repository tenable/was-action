#!/usr/bin/env python
import os, json, time
import sys, traceback
import requests


def get_configuration_id(scan_name, headers):
    """
    Returns the scan config identifier
    """
    url = "https://cloud.tenable.com/was/v2/configs"
    response = requests.request("GET", url, headers=headers)
    response_dict = json.loads(response.text)["data"]

    config_id = None
    for config in response_dict:
        if config["name"] == scan_name:
            config_id = config["config_id"]
            break
    
    if not config_id:
        raise ValueError("Scan configuration not found")

    return config_id


def launch_scan(config_id, headers):
    """
    Will launch an WAS scan with the given config id.
    """
    url = f"https://cloud.tenable.com/was/v2/configs/{config_id}/scans"
    response = requests.request("POST", url, headers=headers)

    response_dict = json.loads(response.text)
    if "scan_id" not in response_dict:
        print(response.text)
        raise ValueError("Scan id not returned")

    return response_dict["scan_id"]

def get_report(scan_id, headers, wait_for_results=False):
    """
    Will get all vulnerabilities for the scan
    
    """
    if not wait_for_results:
        print("Not waiting for report and exiting")
        return

    url = f"https://cloud.tenable.com/was/v2/scans/{scan_id}/report"
    headers["Content-Type"] = "application/json"

    response = requests.request("GET", url, headers=headers)

    while "findings" not in response.text:
        response_dict = json.loads(response.text)
        if response.status_code == 400 and response_dict["reasons"][0]["reason"] == "scan not finalized":
            print(response_dict["reasons"][0]["reason"])
            print("Waiting for 10 minutes")
            time.sleep(10*60)
            response = requests.request("GET", url, headers=headers)
        else:
            print(f"Something went wrong{response.text}")

    findings = json.loads(response.text)["findings"]

    overall_findings = [finding for finding in findings if finding["risk_factor"] in ["low", "medium", "high"]]
    low_severity_findings = [finding for finding in findings if finding["risk_factor"] == "low"]
    medium_severity_findings = [finding for finding in findings if finding["risk_factor"] == "medium"]
    high_severity_findings = [finding for finding in findings if finding["risk_factor"] == "high"]

    return {
        "overall_findings": overall_findings,
        "low_severity_findings": low_severity_findings,
        "medium_severity_findings": medium_severity_findings,
        "high_severity_findings": high_severity_findings
    }

def check_threshold(low_vulns, low_vulns_threshold, medium_vulns, medium_vulns_threshold, high_vulns, high_vulns_threshold):
       
    if low_vulns > low_vulns_threshold:
        raise ValueError("Low severity vulnerabilities found have exceeded threshold")

    if medium_vulns > medium_vulns_threshold:
        raise ValueError("Medium severity vulnerabilities found have exceeded threshold")

    if high_vulns > high_vulns_threshold:
        raise ValueError("High severity vulnerabilities found have exceeded threshold")

def main():

    access_key = str(os.environ["ACCESS_KEY"])
    secret_key = str(os.environ["SECRET_KEY"])

    scan_name = str(os.environ["INPUT_SCAN_NAME"])
    low_vulns_threshold = int(os.environ["INPUT_LOW_VULNS_THRESHOLD"])
    medium_vulns_threshold = int(os.environ["INPUT_MEDIUM_VULNS_THRESHOLD"])
    high_vulns_threshold = int(os.environ["INPUT_HIGH_VULNS_THRESHOLD"])
    block_builds = True if str(os.environ["INPUT_BLOCK_BUILDS"]) == "true" else False
    wait_for_results = True if str(os.environ["INPUT_WAIT_FOR_RESULTS"]) == "true" else False

    headers = {"Accept": "application/json", "x-apikeys": f"accessKey={access_key};secretKey={secret_key}"}

    config_id = get_configuration_id("Test WAS Scan", headers)
    scan_id = launch_scan(config_id, headers)
    report = get_report(scan_id, headers, wait_for_results=wait_for_results)

    if wait_for_results:
        number_of_low_severity_findings = len(report["low_severity_findings"])
        number_of_medium_severity_findings = len(report["medium_severity_findings"])
        number_of_high_severity_findings = len(report["high_severity_findings"])

        if block_builds:
            check_threshold(
                number_of_low_severity_findings,
                low_vulns_threshold,
                number_of_medium_severity_findings,
                medium_vulns_threshold,
                number_of_high_severity_findings,
                high_vulns_threshold
            )

        print(f"::set-output name=number_of_low_severity_findings::{number_of_low_severity_findings}")
        print(f"::set-output name=number_of_medium_severity_findings::{number_of_medium_severity_findings}")
        print(f"::set-output name=number_of_high_severity_findings::{number_of_high_severity_findings}")

if __name__ == "__main__":
    main()