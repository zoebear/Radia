#@file idapy_radia.py
# @author Devin Kinch & Zoe Hardisty. <www.zoehardistydesign.com>
# 		<https://github.com/zoebear/Radia/idapy_radia.py>
# @date June 2015
# @version 0.1
#
# @section LICENSE
#
# The MIT License (MIT)
#
# Copyright (c) 2015 Devin Kinch & Zoe Hardisty
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# @section DESCRIPTION
#
# Used to export binaries out of IDA Pro into functions.json and callgraph.json
# for import into Radia to be visualized.
#

import json
import urllib2

from idaapi import *
from idc import *
from idautils import *

RADIA_URL = 'http://192.168.40.167:5000/api'

categories = {
	'dangerous': {
		"strcpy",
		"lstrcpy",
		"wcscpy",
		"tcscpy",
		"mbscpy",
		"StrCpy",
		"StrCpyA",
		"StrCpyW",
		"lstrcpyA",
		"lstrcpyW",
		"strcpyA",
		"strcpyW",
		"tccpy",
		"mbccpy",
		"strcat",
		"lstrcat",
		"wcscat",
		"tcscat",
		"mbscat",
		"StrCat",
		"StrCatA",
		"StrCatW",
		"lstrcatA",
		"lstrcatW",
		"StrCatBuffW",
		"StrCatBuff",
		"StrCatBuffA",
		"StrCatChainW",
		"strcatA",
		"strcatW",
		"tccat",
		"mbccat",
		"strtok",
		"tcstok",
		"wcstok",
		"mbstok",
		"strccpy",
		"strcadd",
		"gets",
		"getts",
		"gettws",
		"sprintf",
		"swprintf",
		"vswprintf",
		"stprintf",
		"wnsprintf",
		"wnsprintfA",
		"wnsprintfW",
		"sprintfW",
		"sprintfA",
		"wsprintf",
		"wsprintfW",
		"wsprintfA",
		"scanf",
		"vscanf",
		"wscanf",
		"tscanf",
		"sscanf",
		"swscanf",
		"stscanf",
		"fscanf",
		"vsscanf",
		"vfscanf",
		"ftscanf",
		"snscanf",
		"snwscanf",
		"sntscanf",
		"streadd",
		"strecpy",
		"strtrns",
		"system",
		"popen",
		"WinExec",
		"ShellExecute"
	},
	'string': {
		"strncpy",
		"lstrcpyn",
		"wcsncpy",
		"tcsncpy",
		"mbsnbcpy",
		"mbsncpy",
		"StrCpyN",
		"StrCpyNA",
		"StrCpyNW",
		"StrNCpy",
		"strcpynA",
		"StrNCpyA",
		"StrNCpyW",
		"lstrcpynA",
		"lstrcpynW",
		"fstrncpy",
		"strncat",
		"wcsncat",
		"lstrcatn",
		"tcsncat",
		"mbsncat",
		"mbsnbcat",
		"StrCatN",
		"StrCatNA",
		"StrCatNW",
		"StrNCat",
		"StrNCatA",
		"StrNCatW",
		"lstrncat",
		"lstrcatnA",
		"lstrcatnW",
		"fstrncat",
		"printf",
		"vprintf",
		"vwprintf",
		"vtprintf",
		"fprintf",
		"vfprintf",
		"ftprintf",
		"vftprintf",
		"snprintf",
		"vsnprintf",
		"snwprintf",
		"snprintf",
		"sntprintf",
		"nsprintf",
		"vsntprintf",
		"wvsprintf",
		"wvsprintfA",
		"wvsprintfW",
		"vsprintf",
		"vstprintf",
		"vsnprintf",
		"vsnwprintf",
		"wvnsprintf",
		"wvnsprintfA",
		"wvnsprintfW",
		"strlen",
		"wcslen",
		"tcslen",
		"mbslen",
		"mbstrlen",
		"StrLen",
		"lstrlen",
		"MultiByteToWideChar",
		"atoi",
		"atol",
		"itoa",
		"itow",
		"i64toa",
		"i64tow",
		"ui64toa",
		"ui64tot",
		"ui64tow",
		"ultoa",
		"ultot",
		"ultow",
		"CharToOem",
		"CharToOemA",
		"CharToOemW",
		"OemToChar",
		"OemToCharA",
		"OemToCharW",
		"CharToOemBuffA",
		"CharToOemBuffW"
	},
	'crypto': {
		"drand48",
		"erand48",
		"jrand48",
		"lcong48",
		"lrand48",
		"mrand48",
		"nrand48",
		"random",
		"seed48",
		"setstate",
		"srand",
		"strfry",
		"srandom",
		"crypt",
		"EVP_des_ecb",
		"EVP_des_cbc",
		"EVP_des_cfb",
		"EVP_des_ofb",
		"EVP_desx_cbc",
		"EVP_rc4_40",
		"EVP_rc2_40_cbc",
		"EVP_rc2_64_cbc",
		"EVP_aes_128_ctr",
		"EVP_aes_128_ccm",
		"EVP_aes_128_gcm",
		"EVP_aes_128_xts",
		"EVP_aes_128_ecb",
		"EVP_aes_128_cbc",
		"EVP_aes_192_ecb",
		"EVP_aes_192_cbc",
		"EVP_md2",
		"EVP_md4",
		"EVP_md5",
		"EVP_sha1",
		"EVP_sha224",
		"EVP_sha256",
		"EVP_sha384",
		"EVP_sha512"
	},
	'file': {
		"getwd",
		"access",
		"chown",
		"chgrp",
		"chmod",
		"vfork",
		"readlink",
		"tmpfile",
		"tmpnam",
		"tempnam",
		"mktemp",
		"mkstemp",
		"fopen",
		"open",
		"umask",
		"GetTempFileName",
		"realpath",
		"g_get_home_dir",
		"g_get_tmp_dir",
		"fread",
		"readv",
		"Makepath",
		"tmakepath",
		"makepath",
		"wmakepath",
		"splitpath",
		"tsplitpath",
		"wsplitpath",
		"fclose"
	},
	'socket': {
		"recv",
		"recvfrom",
		"recvmsg",
		"send",
		"sento",
		"socket",
		"listen"
	},
	'heap': {
		"calloc",
		"malloc",
		"free",
		"memcpy",
		"CopyMemory",
		"bcopy",
		"IsBadWritePtr",
		"IsBadHugeWritePtr",
		"IsBadReadPtr",
		"IsBadHugeReadPtr",
		"IsBadCodePtr",
		"IsBadStringPtr"
	},
	'system': {
		"getopt",
		"getopt_long",
		"execl",
		"execlp",
		"execle",
		"execv",
		"execvp",
		"CreateProcessAsUser",
		"CreateProcessWithLogon",
		"CreateProcess",
		"chroot",
		"getenv",
		"curl_getenv",
		"RpcImpersonateClient",
		"ImpersonateLoggedOnUser",
		"CoImpersonateClient",
		"ImpersonateNamedPipeClient",
		"ImpersonateDdeClientWindow",
		"ImpersonateSecurityContext",
		"SetThreadToken",
		"InitializeCriticalSection",
		"EnterCriticalSection",
		"LoadLibrary",
		"LoadLibraryEx",
		"SetSecurityDescriptorDacl",
		"AddAccessAllowedAce",
		"getlogin",
		"cuserid",
		"getpw",
		"getpass",
		"gsignal",
		"ssignal",
		"memalign",
		"ulimit",
		"usleep"
	}
}

dangerous_functions = []
for category in categories:
	for func in categories[category]:
		dangerous_functions.append(func)

dangerous_functions_cat = []
for category in categories:
	for func in categories[category]:
		dangerous_functions_cat.append("%s*%s" % (category, func))

# Get the segment's starting address
print "Export Graph Plugin started."
ea = ScreenEA()
functions = {}
links = []
strings = []

def get_bb_info(EA):

  f_start = get_func(EA).startEA
  f_end = FindFuncEnd(f_start)

  edges = set()
  boundaries = set((f_start,))

  # For each defined element in the function.
  for head in Heads(f_start, f_end):

    # If the element is an instruction
    if isCode(GetFlags(head)):

      # Get the references made from the current instruction
      # and keep only the ones local to the function.
      refs = CodeRefsFrom(head, 0)
      refs = set(filter(lambda x: x>=f_start and x<=f_end, refs))

      if refs:
        # If the flow continues also to the next (address-wise)
        # instruction, we add a reference to it.
        # For instance, a conditional jump will not branch
        # if the condition is not met, so we save that
        # reference as well.
        next_head = NextHead(head, f_end)
        if isFlow(GetFlags(next_head)):
          refs.add(next_head)

        # Update the boundaries found so far.
        boundaries.update(refs)

        # For each of the references found, and edge is
        # created.
        for r in refs:
          # If the flow could also come from the address
          # previous to the destination of the branching
          # an edge is created.
          if isFlow(GetFlags(r)):
            edges.add((PrevHead(r, f_start), r))
          edges.add((head, r))

  # Let's build the list of (startEA, startEA) couples
  # for each basic block
  sorted_boundaries = sorted(boundaries, reverse = True)
  end_addr = PrevHead(f_end, f_start)
  bb_addr = []
  for begin_addr in sorted_boundaries:
    bb_addr.append((begin_addr, end_addr))
    # search the next end_addr which could be
    # farther than just the previous head
    # if data are interlaced in the code
    # WARNING: it assumes it won't epicly fail ;)
    end_addr = PrevHead(begin_addr, f_start)
    while not isCode(GetFlags(end_addr)):
      end_addr = PrevHead(end_addr, f_start)
  # And finally return the result
  bb_addr.reverse()
  return bb_addr, sorted(edges)

def add_strings(start, end):
	functions[start]["strings"] = []
	for head in Heads(start, end):
		if isCode(GetFlags(head)):
			data_xrefs = DataRefsFrom(head)
			for xref in data_xrefs:
				if isASCII(GetFlags(xref)):
					strval = str(GetString(xref, -1, 0))
					if len(strval) > 0:
						if strval in strings:
							functions[start]["strings"].append(strings.index(strval) + 1)
						else:
							strings.append(strval)
							functions[start]["strings"].append(strings.index(strval) + 1)
	return None

def add_category(start, end):
	danger = 0
	string = 0
	fileio = 0
	socket = 0
	heap = 0
	crypto = 0
	system = 0
	for head in Heads(start, end):
		if isCode(GetFlags(head)):
			for xref in CodeRefsFrom(head, 0):
				fn = GetTrueName(xref)
				fn = fn.replace('_imp_', '')
				if '@' in fn:
					fn = fn[0:fn.rfind('@')]
				while(True):
					if fn.startswith('_') or fn.startswith('.'):
						fn = fn[1:]
					else:
						break
				print ' ---> ' + repr(fn)
				if fn in dangerous_functions:
					if not (functions[start].has_key("dangerous_list")):
						functions[start]["dangerous_list"] = []
					functions[start]["dangerous_list"].append(dangerous_functions.index(fn) + 1)
					if fn in categories['dangerous']:
						danger = 1
					if fn in categories['string']:
						string = 1
					if fn in categories['file']:
						fileio = 1
					if fn in categories['crypto']:
						crypto = 1
					if fn in categories['socket']:
						socket = 1
					if fn in categories['heap']:
						heap = 1
					if fn in categories['system']:
						system = 1
	functions[start]["category"] = (danger << 6) + (string << 5) + (fileio << 4) + (crypto << 3) + (socket << 2) + (heap << 1) + system
	return None

def add_function(address):
	if not functions.has_key(address):
		if GetFunctionFlags(address) & FUNC_LIB or GetFunctionFlags(address) & FUNC_THUNK:
			print ">>> Skipping " + GetFunctionName(address)
			return None
		name = GetFunctionName(address)
		if not name or name == '':
			name = 'sub_' + ("%08x" % address).upper()
		while(True):
			if name.startswith("?") or name.startswith("_") or name.startswith("$"):
				name = name[1:]
			else:
				break
		if '@@' in name:
			name = name[0:name.find('@@')]

		print "Adding function '%s'" % name
		size = FindFuncEnd(address) - address
		functions[address] = {}
		functions[address]['size'] = size
		functions[address]['name'] = name
		functions[address]['long_name'] = GetFunctionName(address)
		functions[address]['module_name'] = GetInputFile() # for now...
		functions[address]['tag'] = ''
		functions[address]['comment'] = GetFunctionCmt(address, 0)
		functions[address]['basic_blk_cnt'] = len(get_bb_info(address)[0])

		add_category(address, address + size)
		add_strings(address, address + size)
	return None

def add_link(caller, callee):
	link = {}
	link['source'] = caller
	link['target'] = callee
	links.append(link)
	return None

def post_data(api, data):
	json_data = json.dumps(data)
	req = urllib2.Request(RADIA_URL + '/' + api, json_data, {'Content-Type': 'application/json'})
	f = urllib2.urlopen(req)
	response = f.read()
	f.close()
	return response

# Loop through all the functions
print "Building function caller/callee set data..."
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
	add_function(function_ea)
	# For each of the incoming references
	for ref_ea in CodeRefsTo(function_ea, 0):
		func_start = GetFunctionAttr(ref_ea, FUNCATTR_START)
		add_function(func_start)
		add_link(func_start, function_ea)

# Formatting data for API
func_data = { 'functions': [] }
for addr in functions:
	data = functions[addr]
	data['address'] = addr
	func_data['functions'].append(data)

link_data = { 'callgraph': links }
dangerous_data = { 'dangerous': dangerous_functions_cat }
string_data = { 'strings': strings }

# Post to Radia server via JSON
print "Staring new project..."
resp = post_data('new', {})
print repr(resp)

print "Uploading dangerous function list to server..."
resp = post_data('dangerous', dangerous_data)
print repr(resp)

print "Uploading strings table to server..."
resp = post_data('strings', string_data)
print repr(resp)

print "Uploading functions to server..."
resp = post_data('functions', func_data)
print repr(resp)

print "Uploading callgraph to server..."
resp = post_data('callgraph', link_data)
print repr(resp)

print "Done."
