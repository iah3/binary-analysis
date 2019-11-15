/*
 * Copyright 2002-2019 Intel Corporation.
 *
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 *
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <iostream>
#include <fstream>
#include "pin.H"
#include <set>
#include <utility>
#include <string>
#include <sstream>
#include<signal.h>
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

#define CLOSETHREADCOUNT 15

ofstream OutFile;

static UINT64 icount = 0;
static UINT64 syscall = 0;
static bool flag = false;

static std::vector<std::string> rtn_all;
static std::vector<ADDRINT> addr_all;

static int threadCount = 0;
static int closeThreadCount = 0;

static INS per_ins;

std::set<std::string> instr_all;
std::set<std::pair<int, int>> paths;

int flag_19 = 0;
int ins_prev;
std::string ins_prev_string;
// This function is called before every instruction is executed
// and prints the IP
VOID printip(VOID* ip) {
	char all_ins[1000];
	sprintf(all_ins, "%p", ip);
	std::string tmp(all_ins);
	std::stringstream ss;
	ss << std::hex << tmp;
	int ins_cur;
	ss >> ins_cur;
	if (flag_19 == 0) {
		instr_all.insert(tmp);
		if (instr_all.size() > 1) {
			flag_19 = 1;
		}
	}
	else {
		paths.insert(std::make_pair(ins_prev, ins_cur));
	}
	ins_prev = ins_cur;
	ins_prev_string = tmp;
	icount++;
}

VOID Routine(RTN rtn, VOID* v)
{
	string name = RTN_Name(rtn);
	IMG rtn_img = SEC_Img(RTN_Sec(rtn));
	if (IMG_IsMainExecutable(rtn_img))
	{
		RTN_Open(rtn);
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
		{
			// Insert a call to docount before every instruction, no arguments are passed
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
		}
		RTN_Close(rtn);
	}

	return;
}


KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "dotgraph.txt", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
	// Write to a file since cout and cerr maybe closed by the application
	return;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	cerr << "This tool counts the number of dynamic instructions executed" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}


VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 flags, VOID* v)
{
	closeThreadCount++;

	if (closeThreadCount == CLOSETHREADCOUNT) {
		OutFile.setf(ios::showbase);
		OutFile << "digraph controlflow {\n";
		int node_1;
		int node_2;
		for (std::set<std::pair<int, int>>::iterator it = paths.begin(); it != paths.end(); ++it) {
			std::pair<int, int> tmp = *it;

			node_1 = tmp.first;
			std::stringstream s_1;
			s_1 << std::hex << node_1;
			std::string o_1(s_1.str());

			node_2 = tmp.second;
			std::stringstream s_2;
			s_2 << std::hex << node_2;
			std::string o_2(s_2.str());

			OutFile << " \"0x" << o_1 << "\" -> \"0x" << o_2 << "\";\n";
		}
		OutFile << "}";

		OutFile.close();

	}
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char* argv[])
{
	OutFile.open(KnobOutputFile.Value().c_str());

	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();

	PIN_InitSymbols();

	// Register Instruction to be called to instrument instructions
	RTN_AddInstrumentFunction(Routine, 0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}


