#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

def find_tools_recursive(base_path, current_path=""):
    """Recursively find all tools (directories with content.md) in any hierarchical level"""
    tools = []
    
    print(f"Searching in: {base_path} (current_path: '{current_path}')")
    
    if not base_path.exists():
        print(f"Path does not exist: {base_path}")
        return tools
    
    for item in base_path.iterdir():
        print(f"  Checking item: {item.name} (is_dir: {item.is_dir()})")
        
        if not item.is_dir():
            continue
            
        item_relative_path = f"{current_path}/{item.name}" if current_path else item.name
        content_file = item / "content.md"
        
        print(f"    Relative path: {item_relative_path}")
        print(f"    Content file: {content_file}")
        print(f"    Content file exists: {content_file.exists()}")
        
        if content_file.exists():
            # This is a tool directory
            path_parts = item_relative_path.split("/")
            tool_info = {
                "name": item_relative_path,
                "display_name": f"[{path_parts[0]}] {item.name}" if len(path_parts) > 1 else item.name,
                "path": item_relative_path,
                "depth": len(path_parts),
                "tool_name": item.name,
                "categories": path_parts[:-1] if len(path_parts) > 1 else []
            }
            tools.append(tool_info)
            print(f"    -> FOUND TOOL: {tool_info}")
        else:
            # This is a subcategory, recurse into it
            print(f"    -> Recursing into: {item}")
            sub_tools = find_tools_recursive(item, item_relative_path)
            tools.extend(sub_tools)
    
    return tools

def main():
    print("=== Testing Tool Discovery ===")
    
    # Test the tools path
    tools_path = Path("d:/MyPython/NISC_MFPTool_AI/tools")
    print(f"Tools path: {tools_path}")
    print(f"Tools path exists: {tools_path.exists()}")
    
    if not tools_path.exists():
        print("ERROR: Tools path does not exist!")
        return
    
    # List what's in the tools directory
    print("\nContents of tools directory:")
    for item in tools_path.iterdir():
        print(f"  {item.name} (is_dir: {item.is_dir()})")
    
    # Test specific path
    taskafa_path = tools_path / "TaskalfaC3253"
    print(f"\nTaskalfaC3253 path: {taskafa_path}")
    print(f"TaskalfaC3253 exists: {taskafa_path.exists()}")
    
    if taskafa_path.exists():
        print("\nContents of TaskalfaC3253:")
        for item in taskafa_path.iterdir():
            if item.is_dir():
                content_md = item / "content.md"
                print(f"  {item.name} -> has content.md: {content_md.exists()}")
    
    # Test the function
    print("\n=== Running find_tools_recursive ===")
    all_tools = find_tools_recursive(tools_path)
    
    print(f"\n=== RESULTS ===")
    print(f"Total tools found: {len(all_tools)}")
    for i, tool in enumerate(all_tools, 1):
        print(f"{i}. {tool['path']} (depth: {tool['depth']})")

if __name__ == "__main__":
    main()
