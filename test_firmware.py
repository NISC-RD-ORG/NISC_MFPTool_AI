import time
import requests

time.sleep(3)

try:
    response = requests.get('http://localhost:8000/debug-tools')
    data = response.json()
    
    print(f'Status: {response.status_code}')
    print(f'Firmware tools found: {len(data.get("firmware_tools", []))}')
    
    for tool in data.get('firmware_tools', []):
        print(f'  - {tool["name"]}')
        print(f'    Path: {tool.get("path", "N/A")}')
        print(f'    Depth: {tool.get("depth", "N/A")}')
        
    print(f'\nTotal tools found: {data.get("tools_found", 0)}')
        
except Exception as e:
    print(f'Error: {e}')
