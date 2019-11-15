import idaapi
import string
from sets import Set
from idautils import *
from idc import *
from ida_funcs import *
import re, string
from idaapi import *

import os
from sets import Set

from enum import Enum

out_dir = 'outputs'
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

class optype(Enum):
	NONE = 0
	REGISTER = 1
	MEMORY = 2
	BASE_INDEX = 3
	BASE_INDEX_DISP = 4
	IMM = 5
	IMM_FAR = 6
	IMM_NEAR = 7

reg_list = ['al', 'ah', 'ax', 'eax', 'bl', 'bh', 'bx', 'ebx', 'cl', 'ch', 'cx', 'ecx', 'dl', 'dh', 'dx', 'edx', 'si', 'esi', 'di', 'edi', 'sp', 'esp', 'bp', 'ebp']

def write_file(final_string, func_name):
	with open("outputs/" + hex(func_name) + ".dot", "w") as text_file:
		text_file.write(final_string)

def append_node(string_node, node, label, tail):
	return string_node + "	" + node + "	" + "[label = \"" + label + "\"];\n" #+ "; " + tail + "\"];\n"

def append_edge(string_edge, node1, node2):
	return string_edge + "	" + node1 + " -> " + node2 + ";\n"

def final_string_parse(string_node, string_edge):
	return "digraph controlflow {\n" + string_node + "\n\n" + string_edge + "\n}"

def parse_output(nodes, edges, func_name):
	string_edge = ""
	string_node = ""
	d = "def"
	u = "use"
	node_counter = 0
	node_ids = {}

	node_id = 'n' + str(node_counter)
	node_ids['START'] = node_id
	node_counter += 1
	string_node = append_node(string_node, node_id, 'START', '')

	for node in nodes:
		if node == 'START':
			pass
		elif hex(node) not in node_ids.keys():
			node_id = 'n' + str(node_counter)
			node_ids[hex(node)] = node_id
			node_counter += 1
			tail, a, b = def_use_parse(node)
			string_node = append_node(string_node, node_id, hex(node), tail)

	for edge in edges:
		if edge[0] == 'START':
			node1 = node_ids['START']
		elif hex(edge[0]) in node_ids.keys():
			node1 = node_ids[hex(edge[0])]
		else:
			node1 = hex(edge[0])
		if edge[1] == 'START':
			node2 = node_ids['START']
		elif hex(edge[1]) in node_ids.keys():
			node2 = node_ids[hex(edge[1])]
		else:
			node2 = hex(edge[1])
		string_edge = append_edge(string_edge, node1, node2)
		
	final_string = final_string_parse(string_node, string_edge)
	write_file(final_string, func_name)

def parse_indexed_operand(opnd_str):
	ret_list = re.findall('\[(.*)\]', opnd_str)
	split_str = ret_list[0].split('+')
	ret_str = ""

	ret_list2 = list()

	for s in split_str:

		if (s in reg_list):
			if (ret_str == ""):
				ret_str = s
			else:
				ret_str = ret_str + ", " + s
			ret_list2.append(s);

	return ret_list2, ret_str

def parse_use_operand(ea, idx):
	opnd_str = GetOpnd(ea, idx)
	opnd = GetOpType(ea, idx)

	ret_list = list()

	opnd_str = opnd_str.replace('dword ptr ', '')
	opnd_str = opnd_str.replace('byte ptr ', '')

	if (opnd == optype.REGISTER.value):
		ret_str = opnd_str
		ret_list.append(opnd_str)

	if (opnd == optype.IMM.value) or (opnd == optype.IMM_FAR.value) or (opnd == optype.IMM_NEAR.value):
		ret_str = ""

	if (opnd == optype.BASE_INDEX.value) or (opnd == optype.BASE_INDEX_DISP.value):
		ret_list2, ret_str = parse_indexed_operand(opnd_str)
		if (ret_str == ""):
			ret_str = opnd_str
		else:
			ret_str = ret_str + ", " + opnd_str
			ret_list.append(opnd_str)
		ret_list.extend(ret_list2)

	if (opnd  == optype.MEMORY.value):
		if "ds:" in opnd_str:
			ret_str = ""
		else:
			ret_str = opnd_str
			ret_list.append(opnd_str)

	return ret_list, ret_str

def parse_use_of_def_operand(ea, idx):
	opnd_str = GetOpnd(ea, idx)
	opnd = GetOpType(ea, idx)

	ret_list = list()

	opnd_str = opnd_str.replace('dword ptr ', '')
	opnd_str = opnd_str.replace('byte ptr ', '')

	if (opnd == optype.BASE_INDEX.value) or (opnd == optype.BASE_INDEX_DISP.value):
		ret_list2, ret_str = parse_indexed_operand(opnd_str)
		ret_list.extend(ret_list2)
	else:
		ret_str = ""

	return ret_list, ret_str

def parse_def_operand(ea):
	opnd_str = GetOpnd(ea, 0)

	opnd_str = opnd_str.replace('dword ptr ', '')
	opnd_str = opnd_str.replace('byte ptr ', '')

	ret_list = list()
	ret_list.append(opnd_str)

	return ret_list, opnd_str

def push_du(ea):
	def_string = "esp, [esp]"
	def_list = ["esp", "[esp]"]

	use_list, use_string = parse_use_operand(ea, 0) # + ", esp"
	use_string = use_string + ", esp"
	use_list.append("esp")

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def pop_du(ea):
	def_list, def_string = parse_def_operand(ea) # + ", esp"
	def_list.append("esp")
	def_string = def_string + ", esp"

	use_string = "esp, [esp]"
	use_list = ["esp", "[esp]"]

	du_str = "D: " + def_string + " U: " + use_string

	return du_str, def_list, use_list

def mov_du(ea):
	def_list, def_string = parse_def_operand(ea)

	use_list1, use_string1 = parse_use_of_def_operand(ea, 0)
	use_list2, use_string2 = parse_use_operand(ea, 1)

	if (use_string1 != "" and use_string2 != ""):
		use_string = use_string1 + ", " + use_string2
		use_list = use_list1
		use_list.extend(use_list2)
	elif (use_string2 == ""):
		use_string = use_string1
		use_list = use_list1
	elif (use_string1 == ""):
		use_string =  use_string2
		use_list = use_list2
	else:
		use_string = ""
		use_list = list()

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list
	
def binary_alu_du(ea):
	def_list, def_string = parse_def_operand(ea) # + ", eflags"
	def_string = def_string + ", eflags"
	def_list.append("eflags")

	use_list1, use_string1 = parse_use_operand(ea, 0)
	use_list2, use_string2 = parse_use_operand(ea, 1)

	if (use_string1 != "" and use_string2 != ""):
		use_string = use_string1 + ", " + use_string2
		use_list = use_list1
		use_list.extend(use_list2)
	elif (use_string2 == ""):
		use_string = use_string1
		use_list = use_list1
	elif (use_string1 == ""):
		use_string =  use_string2
		use_list = use_list2
	else:
		use_string = ""
		use_list = list()

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def unary_alu_du(ea):
	def_list, def_string = parse_def_operand(ea) # + ", eflags"
	def_string = def_string + ", eflags"
	def_list.append("eflags")

	use_list, use_string = parse_use_operand(ea, 0)

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def cmp_du(ea):
	def_string = "eflags"
	def_list = ["eflags"]

	use_list1, use_string1 = parse_use_operand(ea, 0)
	use_list2, use_string2 = parse_use_operand(ea, 1)

	if (use_string1 != "" and use_string2 != ""):
		use_string = use_string1 + ", " + use_string2
		use_list = use_list1
		use_list.extend(use_list2)
	elif (use_string2 == ""):
		use_string = use_string1
		use_list = use_list1
	elif (use_string1 == ""):
		use_string =  use_string2
		use_list = use_list2
	else:
		use_string = ""
		use_list = list()

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def lea_du(ea):
	def_list, def_string = parse_def_operand(ea)

	use_list1, use_string1 = parse_use_of_def_operand(ea, 0)
	use_list2, use_string2 = parse_use_of_def_operand(ea, 1)

	if (use_string1 != "" and use_string2 != ""):
		use_string = use_string1 + ", " + use_string2
		use_list = use_list1
		use_list.extend(use_list2)
	elif (use_string2 == ""):
		use_string = use_string1
		use_list = use_list1
	elif (use_string1 == ""):
		use_string =  use_string2
		use_list = use_list2
	else:
		use_string = ""
		use_list = list()

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def leave_du(ea):
	def_string = "esp, ebp"
	def_list = ["esp", "ebp"]

	use_string = "ebp, [ebp]"
	use_list = ["ebp", "[ebp]"]

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def call_du(ea):
	def_string = ""
	def_list = list()

	use_list, use_string = parse_use_operand(ea, 0)

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def ret_du(ea):
	def_string = ""
	def_list = list()

	ret_opnd = GetOpType(ea, 0)
	use_string = ""
	use_list = list()

	if (ret_opnd == optype.IMM.value) or (ret_opnd == optype.IMM_FAR.value) or (ret_opnd == optype.IMM_NEAR.value):
		use_string = "esp"
		use_list.append("esp")
		def_string = "esp"
		def_list.append("esp")

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def jump_du(ea):
	def_string = ""
	def_list = list()

	use_string = ""
	use_list = list()

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def jump_cond_du(ea):
	def_string = ""
	def_list = list()

	use_string = "eflags"
	use_list = ["eflags"]

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def stosd_du(ea):
	def_string = "edi, [edi], ecx"
	def_list = ["edi", "[edi]", "ecx"]

	use_string = "eax, edi, eflags, ecx"
	use_list = ["eax", "edi", "eflags", "ecx"]

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def setnz_du(ea):
	def_list, def_string = parse_def_operand(ea)

	use_string = "eflags"
	use_list = ["eflags"]

	du_str = "D: " + def_string + " U: " + use_string
	return du_str, def_list, use_list

def default_du(ea):
	def_string = "UNDEF"
	def_list = list()

	use_string = "UNDEF"
	use_list = list()

	du_str = "D: " + def_string + " U: " + use_string

	return du_str, def_list, use_list

def mnem_to_func(mnem, ea):
	if (mnem == "push"):
		du_str, def_list, use_list = push_du(ea)
	elif (mnem == "pop"):
		du_str, def_list, use_list = pop_du(ea)
	elif (mnem == "mov") or (mnem == 'movsx'):
		du_str, def_list, use_list = mov_du(ea)
	elif (mnem == "lea"):
		du_str, def_list, use_list = lea_du(ea)
	elif (mnem == "cmp") or (mnem == "test"):
		du_str, def_list, use_list = cmp_du(ea)
	elif (mnem == "leave"):
		du_str, def_list, use_list = leave_du(ea)
	elif (mnem == "ret") or (mnem == "retn"):
		du_str, def_list, use_list = ret_du(ea)
	elif (mnem == "call"):
		du_str, def_list, use_list = call_du(ea)
	elif (mnem == "jmp"):
		du_str, def_list, use_list = jump_du(ea)
	elif (mnem == 'ja') or (mnem == 'jb') or (mnem == 'jbe') or (mnem == 'jg') or (mnem == 'jl') or  (mnem == 'jle') or (mnem == 'jnb') or (mnem == 'jnz') or (mnem == 'jz'):
		du_str, def_list, use_list = jump_cond_du(ea)
	elif (mnem == 'add') or (mnem == 'and') or (mnem == 'sub') or (mnem == 'or') or (mnem == 'xor') or (mnem == 'shl') or (mnem == 'sal') or (mnem == 'shr') or (mnem == 'sar'):
		du_str, def_list, use_list = binary_alu_du(ea)
	elif (mnem == 'inc') or (mnem == 'dec'):
		du_str, def_list, use_list = unary_alu_du(ea)
	elif (mnem == 'imul') or (mnem == 'mul') or (mnem == 'idiv') or (mnem == 'div'):
		du_str, def_list, use_list = binary_alu_du(ea)
	elif (mnem == "stosd"):
		du_str, def_list, use_list = stosd_du(ea)
	elif (mnem == "setnz"):
		du_str, def_list, use_list = setnz_du(ea)
	else:
		du_str, def_list, use_list = default_du(ea)

	return du_str, def_list, use_list

def remove_rep(du_str):
	split_str = du_str.split('U:')
	def_str = split_str[0]
	use_str = split_str[1]

	use_split = use_str.split(',')
	use_list = []
	[use_list.append(x) for x in use_split if x not in use_list]
	use_str = ','.join(use_list)
	
	def_use_str = def_str + "U:" + use_str
	return def_use_str

#creates Def-use string and lists for a given instruction (ea)
def def_use_parse(ea):
	mnem_str = GetMnem(ea)
	du_str, def_list, use_list = mnem_to_func(mnem_str, ea)
	du_str = remove_rep(du_str)
	return du_str, def_list, use_list

#returns def list for a given instruction (ea)
def get_def_operand(ea):
	du_str, def_list, use_list = def_use_parse(ea)
	return def_list

#returns use list for a given instruction (ea)
def get_use_operand(ea):
	du_str, def_list, use_list = def_use_parse(ea)
	return use_list

def takeFirst(elem):
	return elem[0]

#function to find instructions that are arguments for a call
def find_call_data_dependence_list(instr, num_arg, f_start, f_end):

	#prepare list of instructions that flow to "instr"
	to_refs = CodeRefsTo(instr, 1)
	to_refs = list(filter(lambda x: x>=f_start and x<=f_end, to_refs))

	refs = list()
	dd_list = list()

	#prepare list of pairs where (tr, n) refer to flow instruction and number of arguments pushed
	for tr in to_refs:
		refs.append((tr, num_arg))

	for r, n in refs:
		mnem = GetMnem(r);

		#if 'n' is 1 and 'r' is a push instruction, this push adds the last argument for call
		if mnem == "push" and n == 1:
			dd_list.append(r)
			n = 0
		else:
			#Append argument corresponding to push to dd_list and decrement number of arguments to handle
			if mnem == "push":
				n -= 1
				dd_list.append(r)
			#Any pop it uses some memory which has been "pushed" but is not an argument to call
			elif mnem == "pop":
				n += 1

			#find references to 'r' and add (r, n) to refs list
			#to handle push arguments that span branches and jumps
			to_refs = CodeRefsTo(r, 1)
			to_refs = list(filter(lambda x: x>=f_start and x<=f_end, to_refs))

			for tr in to_refs:
				tmp = [x[0] for x in refs]
				if tr not in tmp:
					refs.append((tr, n))

	dd_list = list(set(dd_list))
	return dd_list

#function to find instruction that writes to memory for a pop
def find_pop_data_dependence_list(instr, f_start, f_end):

	#prepare list of instructions that flow to "instr"
	to_refs = CodeRefsTo(instr, 1)
	to_refs = list(filter(lambda x: x>=f_start and x<=f_end, to_refs))

	refs = list()
	dd_list = list()

	#prepare list of pairs where (tr, n) refer to flow instruction and number of pops to handle
	for tr in to_refs:
		refs.append((tr, 1))

	for r, n in refs:
		mnem = GetMnem(r);

		#if 'n' is 1 and 'r' is a push instruction, this instruction writes to memory that is popped
		if mnem == "push" and n == 1:
			dd_list.append(r)
			n = 0
		else:
			#Since 'n' is not 1, current push writes to memory which is popped by a different pop instruction
			if mnem == "push":
				n -= 1
			#If a pop instruction is seen, a corresponding push should be ignored for current 'pop'
			#Increase 'n' (number of pops to handle) to keep track of main 'pop' instruction memory
			elif mnem == "pop":
				n += 1
			#Few subroutines clear stack by calling "retn N"; each N corresponds to N/4 pops
			elif mnem == "call":
				call_str = GetOpnd(r, 0)
				call_addr = LocByName(call_str)
				call_end = FindFuncEnd(call_addr)
				call_end = PrevHead(call_end)
				ret_mnem = GetMnem(call_end)
				if ret_mnem == "ret" or ret_mnem == "retn":
					b = GetOpnd(call_end, 0)
					if b != '':
						if b[-1] == 'h':
							b = int(b[:-1], 16)
						else:
							b = int(b)
						n = n + (b/4)
			#'add esp, N' instructions is equivalent to N/4 pops
			elif mnem == "add":
				opnd = GetOpnd(r, 0)
				if opnd == "esp":
					b = GetOpnd(r, 1)
					if b[-1] == 'h':
						b = int(b[:-1], 16)
					else:
						b = int(b)
					n = n + (b/4);

			#find references to 'r' and add (r, n) to refs list
			#to handle push arguments that span branches and jumps
			to_refs = CodeRefsTo(r, 1)
			to_refs = list(filter(lambda x: x>=f_start and x<=f_end, to_refs))

			for tr in to_refs:
				tmp = [x[0] for x in refs]
				if tr not in tmp:
					refs.append((tr, n))

	dd_list = list(set(dd_list))
	return dd_list

#function to find data dependence for a given instr with function bounds f_start and f_end
def find_data_dependence_list(instr, f_start, f_end):

	dd_list = list()

	#starting instruction depends on START
	if instr == f_start:
		dd_list.append('START')

	mnem = GetMnem(instr)

	#find argument list for call instructions
	if mnem == "call":
		addr_list = get_arg_addrs(instr)
		if addr_list:
			num_arg = len(addr_list)
			addr_list = find_call_data_dependence_list(instr, num_arg, f_start, f_end)
			dd_list.extend(addr_list)

	#find push instructions which pop is dependent on
	if mnem == "pop":
		pop_list = find_pop_data_dependence_list(instr, f_start, f_end)
		if pop_list:
			dd_list.extend(pop_list)

	#find data dependencies for elements in the used list (BFS)
	use_list = get_use_operand(instr)

	if use_list:
		for u in use_list:
			#[esp] is used by pop instructions handled in find_pop_data_dependence_list()
			if u == "[esp]":
				continue

			#prepare list of instructions that flow to "instr"
			refs = CodeRefsTo(instr, 1)
			refs = list(filter(lambda x: x>=f_start and x<=f_end, refs))

			for r in refs:
				def_list = get_def_operand(r)

				#if 'u' is defined by instruction 'r', add it to dd_list and end current iteration
				#else find all references to 'r' and add it to 'refs'
				if def_list:
					if u in def_list:
						dd_list.append(r)
					else:
						if r == f_start:
							dd_list.append("START")
							continue
						to_refs = CodeRefsTo(r, 1)
						to_refs = list(filter(lambda x: x>=f_start and x<=f_end, to_refs))
						for tr in to_refs:
							if tr in refs:
								pass
							else:
								refs.append(tr)
				else:
					if r == f_start:
						dd_list.append("START")
						continue
					to_refs = CodeRefsTo(r, 1)
					to_refs = list(filter(lambda x: x>=f_start and x<=f_end, to_refs))
					for tr in to_refs:
						if tr in refs:
							pass
						else:
							refs.append(tr)
	return dd_list

#function traverses all instructions in a subroutine calculating data dependencies for each instruction
def cyclomatic_complexity(function_ea):

	f_start = function_ea
	f_end = FindFuncEnd(function_ea)
	edges = Set()
	nodes = Set((f_start,))

	# For each defined element in the function.
	for instr in Heads(f_start, f_end):

		# If the element is an instruction
		if isCode(GetFlags(instr)):

			#du_str, def_list, use_list = def_use_parse(instr)
			data_dep = find_data_dependence_list(instr, f_start, f_end)
			if data_dep:
				for elem in data_dep:
					edges.add((elem, instr))

			# Get the references made from the current instruction and keep only the ones local to
			# the function.
			refs = CodeRefsFrom(instr, 1)
			refs = Set(filter(lambda x: x>=f_start and x<=f_end, refs))

			if refs:
				# Update the nodes found so far.
				nodes.union_update(refs)

				# For each of the references found, and edge is created.
				for r in refs:
					# CHANGE 1
					pass
					# edges.add((instr, r))

	sortededges = sorted(edges, key = takeFirst);

	sortednodes = sorted(nodes);

	print GetFunctionName(instr) + ' ' + str(len(sortededges)) + ' ' + str(len(sortednodes))

	return sortededges, sortednodes

def do_functions(ea):
	edges = dict()
	nodes = dict()
	func_start = dict()

	# For each of the segments
	for seg_ea in Segments():
		# For each of the functions
		for function_ea in Functions(seg_ea, SegEnd(seg_ea)):
			func_start[GetFunctionName(function_ea)] = function_ea
			edges[GetFunctionName(function_ea)], nodes[GetFunctionName(function_ea)] = cyclomatic_complexity(function_ea)
	

	return edges, nodes, func_start

def do_one_function(ea):
	edges = dict()
	nodes = dict()
	func_start = dict()

	pfn = func_t()
	pfn = get_func(ea)
	func_rangeset = rangeset_t()
	func_range = range_t()
	get_func_ranges(func_rangeset, pfn)
	func_range = func_rangeset.getrange(0)

	ea = func_range.start_ea
	edges[GetFunctionName(ea)], nodes[GetFunctionName(ea)] = cyclomatic_complexity(ea)

	return edges, nodes, func_start



class testplu_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "This is a comment"
	help = "This is help"
	wanted_name = "Lab 4 plugin"
	wanted_hotkey = "Alt-F8"

	def init(self):
		return idaapi.PLUGIN_OK

	def run(self, arg):
		ea = ScreenEA()

		# Collect data
		#edges_all, nodes_all, func_start = do_one_function(ea)
		edges_all, nodes_all, func_start = do_functions(ea)

		# Get the list of functions and sort it.
		functions = edges_all.keys()
		functions.sort()

		# Print the cyclomatic complexity for each of the functions.
		for f in functions:
			edges = []
			nodes = []

			edges = edges + list(edges_all[f])
			nodes = nodes + list(nodes_all[f])

			parse_output(nodes, edges, func_start[f])

	def term(self):
		pass

def PLUGIN_ENTRY():
	return testplu_t()
