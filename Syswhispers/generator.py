import requests
import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="Generate conditionals for getting SSNs by build version discovery at runtime")
    parser.add_argument("-f", "--functions", type=str, required=True, help="NtApis to get, separated by comma")
    return parser.parse_args();


def get_json():
    url="https://raw.githubusercontent.com/j00ru/windows-syscalls/refs/heads/master/x64/json/nt-per-syscall.json"
    req = requests.get(url);
    data = req.json()
    return data


def parse_json(data, ntapi):
    function_data = []
    for win_version, win_value in data[ntapi].items():
        if "XP" in win_version or "2003" in win_version: # Ignore Windows XP and Windows Server 2003
            continue
        for SSN in win_value.values():
            function_data.append(SSN)
    return function_data


def create_function(function_data, ntapi):
    i = 0
    output = f"""
DWORD GetSSN_{ntapi}()
{{
    // Windows Vista
    if (osMajorVersion == 6 && osMinorVersion == 0) {{
        if (buildNumber == 6000) return {function_data[i]}; // SP0
        if (buildNumber == 6001) return {function_data[i+1]}; // SP1
        if (buildNumber == 6002) return {function_data[i+2]}; // SP2
    }}

    // Windows 7
    if (osMajorVersion == 6 && osMinorVersion == 1) {{
        if (buildNumber == 7600) return {function_data[i+3]}; // SP0
        if (buildNumber == 7601) return {function_data[i+4]}; // SP1
    }}

     // Windows 8
    if (osMajorVersion == 6 && osMinorVersion == 2) {{
        if (buildNumber == 9200) return {function_data[i+5]}; // 8.0
    }}

    // Windows 8.1
    if (osMajorVersion == 6 && osMinorVersion == 3) {{
        if (buildNumber == 9600) return {function_data[i+6]}; // 8.1
    }}
    
    // Windows 10/11/Server
    if (osMajorVersion == 10 && osMinorVersion == 0) {{
        switch (buildNumber) {{
            // Windows 10
            case 10240: return {function_data[i+7]}; // 1507
            case 10586: return {function_data[i+8]}; // 1511
            case 14393: return {function_data[i+9]}; // 1607
            case 15063: return {function_data[i+10]}; // 1703
            case 16299: return {function_data[i+11]}; // 1709
            case 17134: return {function_data[i+12]}; // 1803
            case 17763: return {function_data[i+13]}; // 1809
            case 18362: return {function_data[i+14]}; // 1903
            case 18363: return {function_data[i+15]}; // 1909
            case 19041: return {function_data[i+16]}; // 2004
            case 19042: return {function_data[i+17]}; // 20H2
            case 19043: return {function_data[i+18]}; // 21H1
            case 19044: return {function_data[i+19]}; // 21H2
            case 19045: return {function_data[i+20]}; // 22H2
            
            // Windows 11/Server
            case 20348: return {function_data[i+21]}; // Server 2022
            case 22000: return {function_data[i+22]}; // 11 21H2
            case 22621: return {function_data[i+23]}; // 11 22H2
            case 22631: return {function_data[i+24]}; // 11 23H2
            case 25398: return {function_data[i+25]}; // Server 23H2
            case 26100: return {function_data[i+26]}; // 11 24H2 / Server 2025
            case 26200: return {function_data[i+27]}; // 11 25H2

            default:
                // For unknow builds return latest
                if (buildNumber >= 22000) return {function_data[i+26]}; // Last Windows 11
                if (buildNumber >= 10240) return {function_data[i+20]}; // Last Windows 10
                return 0;

        }}
    }}
    return 0;
}}
    """
    print(output)


def main():
    args = parse_args()
    function_list = args.functions.replace(' ','').split(',')
    data = get_json()
    for ntapi in function_list:
        function_data = parse_json(data, ntapi)
        create_function(function_data, ntapi)


if __name__ == "__main__":
    main()
