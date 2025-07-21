import requests
import json

try:
    response = requests.get('http://localhost:8000/listtools')
    data = response.json()
    print(f'Status: {response.status_code}')
    print(f'Response type: {type(data)}')
    
    if isinstance(data, list):
        print(f'Total tools in listtools: {len(data)}')
        # Search for 5-1固件更新
        firmware_tools = [tool for tool in data if "5-1固件更新" in tool.get("name", "")]
        print(f'Found 5-1固件更新 tools: {len(firmware_tools)}')
        
        for tool in firmware_tools:
            print(f'  - {tool["name"]}')
            print(f'    Path: {tool.get("path", "N/A")}')
            print(f'    Display name: {tool.get("display_name", "N/A")}')
    else:
        print(f'API returned: {data}')
        
except Exception as e:
    print(f'Error: {e}')

# Also test the hierarchy API
try:
    print("\n=== Testing hierarchy API ===")
    response = requests.get('http://localhost:8000/hierarchy')
    data = response.json()
    print(f'Hierarchy API status: {response.status_code}')
    print(f'Hierarchy keys: {list(data.keys()) if isinstance(data, dict) else "Not a dict"}')
    
    if isinstance(data, dict) and 'models' in data:
        for model_name, model_data in data['models'].items():
            if 'TaskalfaC3253' in model_name:
                print(f'Found model: {model_name}')
                categories = model_data.get('categories', {})
                for cat_name, cat_data in categories.items():
                    if '5-1' in cat_name or '固件' in cat_name:
                        print(f'  Category: {cat_name} - {len(cat_data.get("tools", []))} tools')
                        
except Exception as e:
    print(f'Hierarchy API Error: {e}')
