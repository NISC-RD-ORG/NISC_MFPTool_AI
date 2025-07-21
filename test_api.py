import requests
import json

try:
    response = requests.get('http://localhost:8000/debug-tools')
    data = response.json()
    print(f'Status: {response.status_code}')
    print(f'Response keys: {list(data.keys())}')
    print(f'Total tools found: {data.get("tools_found", 0)}')
    
    # Print full response for debugging
    print(f'Full response: {json.dumps(data, indent=2, ensure_ascii=False)}')
    
    # Check if 5-1固件更新 is found
    tools_with_firmware = [tool for tool in data.get("tools", []) if "5-1固件更新" in tool["name"]]
    print(f'Found 5-1固件更新: {len(tools_with_firmware) > 0}')
    
    if tools_with_firmware:
        for tool in tools_with_firmware:
            print(f'  - {tool["name"]} (depth: {tool.get("depth", "unknown")})')
        
except Exception as e:
    print(f'Error: {e}')
