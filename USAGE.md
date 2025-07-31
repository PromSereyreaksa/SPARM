# 🚀 SPARM Usage Guide

## How to Run SPARM

### ✅ **Recommended Way: Use the Launcher**
```bash
python3 sparm.py
```

**What this does:**
- Automatically activates the virtual environment
- Launches the main SPARM application
- Handles all dependencies correctly
- Provides clean error messages if setup is incomplete

### 🔧 **Alternative: Direct Execution**
```bash
# Activate virtual environment first
source venv/bin/activate

# Then run main application
python3 sparm_main.py
```

### 📁 **File Structure:**
- **`sparm.py`** → Launcher script (recommended entry point)
- **`sparm_main.py`** → Main application code
- **`core/`** → Core utilities and configuration
- **`modules/`** → Security tool modules
- **`wordlists/`** → SecList wordlists (symlinked)
- **`logs/`** → Session logs and test results

### 🎯 **Quick Start:**
```bash
# 1. Run SPARM
python3 sparm.py

# 2. Navigate to Enhanced Hydra
# Main Menu → Credential Access Tools → Hydra

# 3. Test with DVWA
# Target: localhost:8080
# Service: http-post-form
# Wordlists: Browse SecList categories!
```

### ✅ **What's Fixed:**
- ✅ Syntax error resolved
- ✅ Real-time verbose output working  
- ✅ SecList wordlist integration active
- ✅ Custom wordlist paths supported
- ✅ Session logging functional
- ✅ Clean project structure

**Always use `python3 sparm.py` to launch SPARM!** 🎉