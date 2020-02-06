/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {
#include <stdint.h>    
}

#include "panda/plugin.h"

#include "taint2/taint2.h"

extern "C" {
#include "taint2/taint2_ext.h"
}

// NB: callstack_instr_ext needs this, sadly
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"


#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include <map>
#include <set>
#include <iostream>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
void taint_change(void);

}


extern ram_addr_t ram_size;

#include <map>
#include <set>

// map from pid -> addr
std::map<uint64_t,std::set<uint64_t>> tainted_memory_read;
std::map<uint64_t,std::set<uint64_t>> tainted_memory_write;

target_ulong last_asid = 0;
target_ulong last_pc = 0;

Addr make_maddr(uint64_t a) {
  Addr ma;
  ma.typ = MADDR;
  ma.val.ma = a;
  ma.off = 0;
  ma.flag = (AddrFlag) 0;
  return ma;
}

void before_virt_ops(CPUState *env, target_ptr_t addr,
                     size_t size, std::map<uint64_t,std::set<uint64_t>>  & tainted_memory_map)
{
    if (!taint2_enabled()){
        return;
    }
    hwaddr ma = panda_virt_to_phys(env, addr);

    uint32_t num_tainted = 0;
    for (uint32_t i=0; i<size; i++) {
        uint64_t cur_ram = ma + i;
        if(ram_size < cur_ram){
            //-m 2048
            continue;
        }
        num_tainted += (taint2_query_ram(cur_ram) != 0);
    }

    if (0 < num_tainted){
        OsiProc *current_proc = get_current_process(env);
        target_ulong pid = current_proc->pid;
        //printf("tainted addr: %x, refrenced by pid: %d\n", (unsigned int)addr, (unsigned int)pid);
        tainted_memory_map[pid].insert(addr);
    }
    return;

}

void before_virt_read(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                     size_t size) {
    //printf("[taint_memory]%x is reading %x\n", (unsigned int)pc, (unsigned int)addr);
    before_virt_ops(env, addr, size, tainted_memory_read);
    return;
}


void before_virt_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t *buf) {
    //printf("[taint_memory]%x is writing %x\n", (unsigned int)pc, (unsigned int)addr);
    before_virt_ops(env, addr, size, tainted_memory_write);
    return;
}





bool init_plugin(void *self) {
    panda_require("taint2");
    assert(init_taint2_api());
    panda_require("callstack_instr");
    assert (init_callstack_instr_api());
    panda_require("osi");
    assert(init_osi_api());

    panda_enable_precise_pc();
    panda_enable_memcb();

    //panda_arg_list *args = panda_get_args("tainted_memory");
    //summary = panda_parse_bool_opt(args, "summary", "summary tainted memory info");
    //num_tainted_instr = panda_parse_uint64_opt(args, "num", 0, "number of tainted memory to log or summarize");
    //if (summary) printf ("tainted_memory summary mode\n");
    puts("[tainted_memory]tainted_memory full mode");

    panda_cb pcb;    
    pcb.virt_mem_before_read = before_virt_read;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    pcb.virt_mem_after_write = before_virt_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);

    taint2_track_taint_state();
    return true;
}

void uninit_plugin(void *self) {
    /*
    if (summary) {
        Panda__TaintedInstrSummary *tis = (Panda__TaintedInstrSummary *) malloc (sizeof (Panda__TaintedInstrSummary));
        for (auto kvp : tainted_instr) {
            uint64_t asid = kvp.first;
            if (!pandalog) 
                printf ("tainted_instr: asid=0x%" PRIx64 "\n", asid);
            for (auto pc : kvp.second) {
                if (pandalog) {
                    *tis = PANDA__TAINTED_INSTR_SUMMARY__INIT;
                    tis->asid = asid;
                    tis->pc = pc;
                    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                    ple.tainted_instr_summary = tis;
                    pandalog_write_entry(&ple);
                }
                else {
                    printf ("  pc=0x%" PRIx64 "\n", (uint64_t) pc);
                }
            }
        }
        free(tis);
    }
    */
   puts("[tainted_memory]on uninit\n");
   for(auto cur_item: tainted_memory_read){
       auto pid = cur_item.first;
       for(auto addr: cur_item.second){
           std::cout << pid << " reading "  << addr << std::hex<< std::endl;
       }
   }
   for(auto cur_item: tainted_memory_write){
       auto pid = cur_item.first;
       for(auto addr: cur_item.second){
           std::cout << pid << " writing "  << addr << std::hex << std::endl;
       }
   }
   return;
}
