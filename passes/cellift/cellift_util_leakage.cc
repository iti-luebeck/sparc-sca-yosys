// SPDX-License-Identifier: ISC
// Copyright (C) 2024-2026 Andrija Neskovic, University of Luebeck
// Power leakage extension; base CellIFT pass: Copyright (C) 2020 Alberto Gonzalez & Flavien Solt

#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"
#include <algorithm>
#include <cctype>

USING_YOSYS_NAMESPACE

// Forward declaration of utility function from cellift_util.cc
extern bool is_signal_excluded(std::vector<string> *excluded_signals, string signal_name);

// Transforms an identifier name into the corresponding power leakage name.
// Mirrors get_wire_taint_idstring() but uses "_leak" instead of "_t" suffix.
std::string get_wire_leakage_idstring(RTLIL::IdString id_string, unsigned int leakage_id) {
    return id_string.str() + "_leak" + std::to_string(leakage_id);
}

// For a given SigSpec, returns the corresponding power leakage SigSpec.
// Mirrors get_corresponding_taint_signals() but for leakage shadows.
// 
// This function creates or retrieves leakage shadow wires for each bit in the input signal.
// Unlike taint signals which propagate information flow, leakage signals track power-observable
// switching activity on tainted paths.
//
// Args:
//   module: The module containing the signals
//   excluded_signals: Signals to exclude from leakage tracking (e.g., clock/reset)
//   sig: The original signal to create leakage shadows for
//   num_leakages: Number of distinct leakage labels (usually 1 per taint label)
//
// Returns:
//   Vector of SigSpecs, one for each leakage label, containing leakage shadow wires
std::vector<RTLIL::SigSpec> get_corresponding_leakage_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_leakages) {
    std::vector<RTLIL::SigSpec> ret(num_leakages);

    // Get a SigSpec for the corresponding leakage signal for the given signal, creating a new SigSpec if necessary.
    for (unsigned int leakage_id = 0; leakage_id < num_leakages; leakage_id++) {
        for (auto &chunk_it: sig.chunks()) {

            if (chunk_it.is_wire() && !is_signal_excluded(excluded_signals, chunk_it.wire->name.str())) {
                RTLIL::Wire *w = module->wire(get_wire_leakage_idstring(chunk_it.wire->name.str(), leakage_id));
                if (w == nullptr) {
                    // Create new leakage wire with same width and properties as original
                    w = module->addWire(get_wire_leakage_idstring(chunk_it.wire->name.str(), leakage_id), chunk_it.wire);
                    w->port_input = false;
                    // Phase 2 Port Promotion: Make leakage wires visible as output ports
                    // This allows leakage signals to be observed in simulation traces
                    w->port_output = true;
                }
                ret[leakage_id].append(RTLIL::SigChunk(w, chunk_it.offset, chunk_it.width));
            }
            else
                // Non-data signals (constants, excluded signals) have no leakage
                ret[leakage_id].append(RTLIL::SigChunk(RTLIL::State::S0, chunk_it.width));
        }
        log_assert(ret[leakage_id].size() == sig.size());
    }
    return ret;
}

// Helper function to check if a signal is clock or reset (should not leak)
bool is_clock_or_reset_signal(RTLIL::IdString signal_name) {
    std::string name_lower = signal_name.str();
    // Convert to lowercase for comparison
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
    
    // Check for common clock/reset naming patterns
    return (name_lower.find("clk") != std::string::npos ||
            name_lower.find("rst") != std::string::npos ||
            name_lower.find("reset") != std::string::npos ||
            name_lower.find("clock") != std::string::npos);
}
