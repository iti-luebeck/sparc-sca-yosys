#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE
extern std::vector<RTLIL::SigSpec> get_corresponding_taint_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_taints);
extern std::string get_wire_leakage_idstring(RTLIL::IdString id_string, unsigned int leakage_id);
extern std::vector<RTLIL::SigSpec> get_corresponding_leakage_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_leakages);

/**
 * @param module the current module instance
 * @param cell the current cell instance
*
 * @return keep_current_cell
 */
bool cellift_xor(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals) {

    const unsigned int A = 0, B = 1, Y = 2;
    const unsigned int NUM_PORTS = 3;
    RTLIL::SigSpec ports[NUM_PORTS] = {cell->getPort(ID::A), cell->getPort(ID::B), cell->getPort(ID::Y)};
    std::vector<RTLIL::SigSpec> port_taints[NUM_PORTS];
    std::vector<RTLIL::SigSpec> port_leakages[NUM_PORTS];

    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_taints[i] = get_corresponding_taint_signals(module, excluded_signals, ports[i], num_taints);
    
    // Phase 3: Get leakage shadows for output port (simplified model: leak = taint)
    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_leakages[i] = get_corresponding_leakage_signals(module, excluded_signals, ports[i], num_taints);

    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        module->addOr(NEW_ID, port_taints[A][taint_id], port_taints[B][taint_id], port_taints[Y][taint_id]);
        
        // Phase 3: Drive leakage output with taint (simplified model for combinational)
        RTLIL::SigSpec leakage_output = port_taints[Y][taint_id];
        
        // Connect to output port if this xor output is a module port
        if (ports[Y].is_wire() && ports[Y].as_wire()->port_output) {
            // Get the leakage port for this output
            std::string leak_name = get_wire_leakage_idstring(ports[Y].as_wire()->name.str(), taint_id);
            RTLIL::Wire *leak_port = module->wire(RTLIL::IdString(leak_name));
            
            if (leak_port && leak_port->port_output) {
                // Connect internal leakage logic to the output port
                module->connect(leak_port, leakage_output);
            }
        }
        
        // Always connect internal leakage wire (for non-port signals and hierarchy)
        module->connect(port_leakages[Y][taint_id], leakage_output);
    }

    return true;
}
