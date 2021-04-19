from  src.main import main
import pytest, json, mock

@mock.patch("src.main.main.requests")
def test_get_configuration_id(mock_requests):
    mock_requests.request().status_code = 200
    mock_requests.request().text = json.dumps({
        "data": [{
            "name": "scan_name",
            "config_id": "config_id"
        }]
    })
    assert main.get_configuration_id("folder_name", "scan_name", headers={}) == "config_id"
    

@mock.patch("src.main.main.requests")
def test_get_configuration_id_not_found(mock_requests):
    with pytest.raises(ValueError):
        mock_requests.request().status_code = 200 
        mock_requests.request().text = json.dumps({
            "data": [{
                "name": "scan_name_1",
                "config_id": "config_id"
            }]
        })
        main.get_configuration_id("folder_name", "scan_name", headers={})

@mock.patch("src.main.main.requests")
def test_get_configuration_id_status_code_not_200(mock_requests):
    with pytest.raises(ValueError):
        mock_requests.request().text = json.dumps({
            "reasons": [{
                "reason": "unknown"
            }]
        })
        main.get_configuration_id("folder_name", "scan_name", headers={})


@mock.patch("src.main.main.requests")
def test_launch_scan(mock_requests):
    mock_requests.request().status_code = 202 
    mock_requests.request().text = json.dumps({
        "scan_id": "scan_id"
    })
    assert main.launch_scan("config_id", headers={}) == "scan_id"

@mock.patch("src.main.main.requests")
def test_launch_scan_with_error(mock_requests):
    with pytest.raises(ValueError):
        mock_requests.request().status_code = 400 
        mock_requests.request().text = json.dumps({
            "reasons": [
                {
                    "reason": "launch with error"
                }
            ]
        })
        main.launch_scan("config_id", headers={}) == "scan_id"

@mock.patch("src.main.main.requests")
def test_get_report(mock_requests):
    mock_requests.request().status_code = 200
    mock_requests.request().text = json.dumps({
        "findings": [{
            "risk_factor": "low"
        },{
            "risk_factor": "high"
        },{
            "risk_factor": "medium"
        }]
    })
    overall_findings = [{
            "risk_factor": "low"
        },{
            "risk_factor": "high"
        },{
            "risk_factor": "medium"
    }]
    low_findings = [{
            "risk_factor": "low"
    }]
    medium_findings = [{
            "risk_factor": "medium"
    }]
    high_findings = [{
            "risk_factor": "high"
    }]
    critical_findings = []
    
    assert main.get_report("scan_id", headers={}) == {
        "overall_findings": overall_findings,
        "high_severity_findings": high_findings,
        "low_severity_findings": low_findings,
        "medium_severity_findings": medium_findings,
        "critical_severity_findings": critical_findings
    }


@mock.patch("src.main.main.requests")
def test_get_report_with_info(mock_requests):
    mock_requests.request().status_code = 200
    mock_requests.request().text = json.dumps({
        "findings": [{
            "risk_factor": "low"
        },{
            "risk_factor": "high"
        },{
            "risk_factor": "medium"
        }, {
             "risk_factor": "info"
        }, {
            "risk_factor": "critical"
        }]
    })
    overall_findings = [{
            "risk_factor": "low"
        },{
            "risk_factor": "high"
        },{
            "risk_factor": "medium"
        }, {
            "risk_factor": "critical"
    }]
    low_findings = [{
            "risk_factor": "low"
    }]
    medium_findings = [{
            "risk_factor": "medium"
    }]
    high_findings = [{
            "risk_factor": "high"
    }]
    critical_findings = [{
            "risk_factor": "critical"
    }]
    
    assert main.get_report("scan_id", headers={}) == {
        "overall_findings": overall_findings,
        "high_severity_findings": high_findings,
        "low_severity_findings": low_findings,
        "medium_severity_findings": medium_findings,
        "critical_severity_findings": critical_findings
    }

def test_check_threshold():
    with pytest.raises(ValueError):
        main.check_threshold(10, 5, 5, 10, 5, 10, 5, 10)
