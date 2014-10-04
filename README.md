DLLRunner
=========

DLLRunner is a clever DLL execution script for malware analysis in sandbox systems. Instead of executing a DLL file via "rundll32.exe file.dll" it analyzes the PE and executes all exported functions by name or ordinal in order to determine if one of the functions causes malicious activity. 
Furthermore it tries to fuzz parameters in order to trigger acitivity in functions that require parameters to work. 

Usage
=========
usage: dllrunner.py [-h] [-f dllfile] [--fuzz] [--demo] [--debug]

DLLRunner

optional arguments:
  -h, --help  show this help message and exit
  -f dllfile  DLL file to execute exported functions
  --fuzz      Add fuzzing parameters to the functions calls (currently 5
              params are defined)
  --demo      Run a demo using \system32\url.dll
  --debug     Debug output
