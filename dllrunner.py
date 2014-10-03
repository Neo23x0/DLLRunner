#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# DLLRunner
# Executes all DLL exports 
#
# Florian Roth
# v0.1
# October 2014

import pefile
import argparse
from subprocess import Popen


def analyze(dll_file):

	# Export dictionary
	exports = []
	
	pe = pefile.PE(dll_file)
	
	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		# print exp.name, exp.ordinal
		exports.append((exp.name, exp.ordinal))
		
	return exports

	
def run(dll_file, exports):
	
	for export in exports:
		exp_name    = export[0]
		exp_ordinal = export[1]
		
		# Executing exported function by ordinal as it has no name
		if exp_name:
			if args.debug:
				print "Executing via Name: rundll32.exe %s %s" % ( dll_file, exp_name )
			p = Popen(['rundll32.exe', dll_file, exp_name])
		
		# Executing exported function by name
		else:
			if args.debug:
				print "Executing via Ordinal: rundll32.exe %s %s" % ( dll_file, exp_ordinal )
			#p = Popen(['rundll32.exe,%s' % dll_file, exp_ordinal])
	
	
# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='DLLRunner')
	parser.add_argument('-f', help='DLL file to execute exported functions')
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# Get all exports
	exports = analyze(args.f)

	# Execute the DLL exports
	run(args.f, exports)