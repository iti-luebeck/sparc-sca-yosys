// SPDX-License-Identifier: ISC
// Copyright (C) 2024-2026 Andrija Neskovic, University of Luebeck
// Power leakage extension; base CellIFT pass: Copyright (C) 2020 Alberto Gonzalez & Flavien Solt

#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE

extern std::vector<RTLIL::SigSpec> get_corresponding_taint_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_taints);
extern std::string get_wire_leakage_idstring(RTLIL::IdString id_string, unsigned int leakage_id);
extern std::vector<RTLIL::SigSpec> get_corresponding_leakage_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_leakages);

/**
 * cellift_dff_with_leakage: Flip-flop handler with power leakage tracking
 * 
 * Instruments a D flip-flop to track both information flow (taint) and power
 * side-channel leakage. Power leakage occurs when a tainted signal transitions,
 * as transitions consume power and are detectable through power analysis.
 * 
 * Architecture:
 *   - For each taint label, create a corresponding leakage label
 *   - Track transitions: Q XOR Q_prev (delayed Q output)
 *   - Leakage formula: leak = transition AND taint
 *   - Only transitions on tainted paths contribute to observable leakage
 * 
 * @param module the current module instance
 * @param cell the current D flip-flop cell instance
 * @param num_taints number of distinct taint labels
 * @param excluded_signals signals to exclude from tracking
 * @return keep_current_cell (always true - we want to keep original DFF)
 */
bool cellift_dff_with_leakage(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals) {

    const unsigned int CLK = 0, D = 1, Q = 2;
    const unsigned int NUM_PORTS = 3;
    RTLIL::SigSpec ports[NUM_PORTS] = {cell->getPort(ID::CLK), cell->getPort(ID::D), cell->getPort(ID::Q)};
    
    // Get taint shadows for all ports
    std::vector<RTLIL::SigSpec> port_taints[NUM_PORTS];
    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_taints[i] = get_corresponding_taint_signals(module, excluded_signals, ports[i], num_taints);
    
    // Get leakage shadows for all ports (will be driven by leakage logic)
    std::vector<RTLIL::SigSpec> port_leakages[NUM_PORTS];
    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_leakages[i] = get_corresponding_leakage_signals(module, excluded_signals, ports[i], num_taints);

    // Create shadow flip-flops for taint tracking (standard CellIFT behavior)
    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        RTLIL::Cell *new_ff = module->addDff(NEW_ID, ports[CLK], port_taints[D][taint_id], port_taints[Q][taint_id], cell->getParam(ID(CLK_POLARITY)).as_bool());
        new_ff->set_bool_attribute(ID(taint_ff));
    }

    // Create leakage tracking logic for each taint label
    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        
        // Step 1: Create delayed Q signal (Q_prev = Q from previous cycle)
        // Capture the functional Q value to detect real switching activity.
        RTLIL::SigSpec Q_prev_wire = module->addWire(NEW_ID, ports[Q].size());
        RTLIL::Cell *delay_ff = module->addDff(NEW_ID, ports[CLK], ports[Q], Q_prev_wire, cell->getParam(ID(CLK_POLARITY)).as_bool());
        delay_ff->set_bool_attribute(ID(leakage_delay_ff));
        
        // Step 2: Detect transitions in Q: transition = Q XOR Q_prev
        // This captures when the output changes, indicating power consumption
        RTLIL::SigSpec transition = module->Xor(NEW_ID, ports[Q], Q_prev_wire);
        
        // Step 3: Combine transition detection with taint information
        // Leakage = transition AND taint_Q
        // This ensures we only record leakage when:
        // (a) The output actually transitions (power is consumed)
        // (b) The transition is on a tainted path (key-dependent)
        RTLIL::SigSpec leakage_output = module->And(NEW_ID, transition, port_taints[Q][taint_id]);
        
        // Step 4: Drive the leakage shadow output
        // Connect to output port if this DFF output is a module port
        if (ports[Q].is_wire() && ports[Q].as_wire()->port_output) {
            // Get the leakage port for this output
            std::string leak_name = get_wire_leakage_idstring(ports[Q].as_wire()->name.str(), taint_id);
            RTLIL::Wire *leak_port = module->wire(RTLIL::IdString(leak_name));
            
            if (leak_port && leak_port->port_output) {
                // Connect internal leakage logic to the output port
                module->connect(leak_port, leakage_output);
            }
        }
        
        // Always connect internal leakage wire (for non-port signals and hierarchy)
        module->connect(port_leakages[Q][taint_id], leakage_output);
    }

    return true;
}
