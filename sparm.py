#!/usr/bin/env python3
"""
SPARM Launcher - Security Penetration & Research Multitool
Quick launcher that handles virtual environment activation
"""

import os
import sys
import subprocess

def main():
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(script_dir, "venv", "bin", "python")
    main_script = os.path.join(script_dir, "sparm_main.py")
    
    # Check if virtual environment exists
    if not os.path.exists(venv_python):
        print("❌ Virtual environment not found!")
        print("Please run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt")
        sys.exit(1)
    
    # Check if main script exists
    if not os.path.exists(main_script):
        print("❌ Main script not found!")
        sys.exit(1)
    
    try:
        # Launch SPARM using the virtual environment
        subprocess.run([venv_python, main_script] + sys.argv[1:])
    except KeyboardInterrupt:
        print("\n\n👋 SPARM terminated by user")
    except Exception as e:
        print(f"❌ Error launching SPARM: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()