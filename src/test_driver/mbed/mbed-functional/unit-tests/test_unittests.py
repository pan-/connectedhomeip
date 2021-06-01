import pytest
import re

@pytest.mark.smoketest
def test_chip_unit_tests(device):
    lines = device.wait_for_output("CHIP:-: CHIP test status:", 500)
    # extract number of failures: 
    last_line = lines[-1]
    result = re.findall(r'\d+', last_line)
    assert len(result) == 1
    assert result[0] == 0
