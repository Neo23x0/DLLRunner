#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# DLLRunner
# Executes all DLL exports 
#
# Florian Roth
# v0.2a
# October 2014

import os
import pefile
import argparse
import traceback
from subprocess import Popen

FUZZ_PARAMS = [ 'http://evil.local', 'evil.com', '0', '1', 'Install' ]


def analyze(dll_file):

	# Debug
	if args.debug:
		print "Analysing: %s" % dll_file

	# Export dictionary
	exports = []
	
	try:
		pe = pefile.PE(dll_file)
		
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			# print exp.name, exp.ordinal
			exports.append((exp.name, exp.ordinal))
			
		return exports
		
	except Exception, e:
		traceback.print_exc()
		
	finally:
		return exports
	

	
def run(dll_file, exports):
	
	# Loop through detected function exports
	for export in exports:
		exp_name    = export[0]
		exp_ordinal = export[1]
		
		# Evaluate function identifier
		func_ident = exp_ordinal
		if exp_name:
			func_ident = exp_name
		
		# Executing exported function
		if exp_name:		
			# Debug output
			if args.debug:
				print "Executing: rundll32.exe %s %s" % ( dll_file, func_ident )				
			# Executing function
			p = Popen(['rundll32.exe', dll_file, func_ident])			
			# Fuzzing
			if args.fuzz:
				for fuzz_param in FUZZ_PARAMS:
					p = Popen(['rundll32.exe', dll_file, func_ident, fuzz_param])
	
	
# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='DLLRunner')
	parser.add_argument('-f', metavar="dllfile", help='DLL file to execute exported functions')
	parser.add_argument('--fuzz', action='store_true', default=False, help='Add fuzzing parameters to the functions calls (currently %s params are defined)' % len(FUZZ_PARAMS) )
	parser.add_argument('--demo', action='store_true', default=False, help='Run a demo using \\system32\\url.dll')
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# DLL file
	dllfile = args.f
	
	# Demo mode
	if args.demo:
		dllfile = "%s\\system32\\url.dll" % os.environ["SYSTEMROOT"]
	
	# Get all exports
	exports = analyze(dllfile)

	# Execute the DLL exports
	run(dllfile, exports)