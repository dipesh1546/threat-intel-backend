#!/usr/bin/env python3
"""
Parse MITRE CWE XML file and extract all CWE weaknesses
"""

import xml.etree.ElementTree as ET
import json
import re
from pathlib import Path

def parse_cwe_xml(xml_path: Path) -> list:
    """Parse MITRE CWE XML and extract all CWEs"""
    
    def get_severity(cwe_id: int, name: str, description: str) -> str:
        # Critical severity CWEs
        critical_ids = [78, 79, 89, 94, 119, 120, 121, 122, 287, 306, 502, 611, 798, 918]
        if cwe_id in critical_ids:
            return "critical"
        
        # High severity CWEs
        high_ids = [20, 22, 74, 77, 80, 90, 91, 125, 129, 131, 134, 190, 200, 264, 269, 284, 285, 352, 362, 367, 400, 416, 434, 476, 601, 862, 863]
        if cwe_id in high_ids:
            return "high"
        
        # Check name for keywords
        name_lower = name.lower()
        desc_lower = description.lower()
        
        if any(k in name_lower or k in desc_lower for k in ["buffer overflow", "command injection", "sql injection", "code injection"]):
            return "critical"
        if any(k in name_lower or k in desc_lower for k in ["xss", "cross-site", "path traversal", "privilege", "authentication"]):
            return "high"
        
        return "medium"
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        weaknesses = []
        
        # Find the Weaknesses container
        weaknesses_container = root.find(".//{http://cwe.mitre.org/cwe-7}Weaknesses")
        if weaknesses_container is None:
            print("Could not find Weaknesses container")
            return []
        
        print(f"Found Weaknesses container, parsing {len(weaknesses_container)} entries...")
        
        for weakness in weaknesses_container.findall("{http://cwe.mitre.org/cwe-7}Weakness"):
            # Get ID from attributes
            cwe_id = weakness.get("ID")
            if not cwe_id:
                continue
            
            try:
                cwe_num = int(cwe_id)
            except:
                continue
            
            # Get Name from attributes
            name = weakness.get("Name", "")
            if not name:
                continue
            
            # Get Description
            description = ""
            desc_elem = weakness.find("{http://cwe.mitre.org/cwe-7}Description")
            if desc_elem is not None:
                # Get text from Description element
                if desc_elem.text:
                    description = desc_elem.text
                else:
                    # Check children
                    for child in desc_elem:
                        if child.tag == "{http://cwe.mitre.org/cwe-7}Text" and child.text:
                            description = child.text
                            break
            
            # Clean description
            if description:
                # Remove HTML tags
                description = re.sub(r'<[^>]+>', ' ', description)
                description = ' '.join(description.split())
                description = description[:400]
            else:
                description = f"{name} weakness in software security."
            
            # Determine severity
            severity = get_severity(cwe_num, name, description)
            
            weaknesses.append({
                "id": f"CWE-{cwe_num}",
                "name": name,
                "severity": severity,
                "description": description
            })
            
            if len(weaknesses) % 200 == 0:
                print(f"  Processed {len(weaknesses)} CWEs...")
        
        return weaknesses
        
    except Exception as e:
        print(f"Error parsing XML: {e}")
        import traceback
        traceback.print_exc()
        return []

def main():
    # Find the XML file
    data_dir = Path(__file__).parent.parent / "data"
    xml_files = list(data_dir.glob("cwec_v*.xml"))
    
    if not xml_files:
        print("No CWE XML file found.")
        return
    
    xml_file = xml_files[0]
    print(f"Parsing {xml_file}...")
    
    weaknesses = parse_cwe_xml(xml_file)
    print(f"\nFound {len(weaknesses)} CWEs")
    
    if weaknesses:
        # Sort by CWE ID
        weaknesses.sort(key=lambda x: int(x["id"].split("-")[1]))
        
        # Save to JSON
        output_file = data_dir / "cwe_complete.json"
        with open(output_file, 'w') as f:
            json.dump(weaknesses, f, indent=2)
        
        print(f"✅ Saved {len(weaknesses)} CWEs to {output_file}")
        
        # Show stats
        severity_counts = {
            "critical": len([w for w in weaknesses if w["severity"] == "critical"]),
            "high": len([w for w in weaknesses if w["severity"] == "high"]),
            "medium": len([w for w in weaknesses if w["severity"] == "medium"])
        }
        print("\nSeverity Distribution:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        # Show sample
        print("\nSample CWEs:")
        for cwe in weaknesses[:10]:
            print(f"  {cwe['id']}: {cwe['name'][:60]}")
    else:
        print("No CWEs found in XML file")

if __name__ == "__main__":
    main()
