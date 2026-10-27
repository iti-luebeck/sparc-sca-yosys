/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2020  Alberto Gonzalez <boqwxp@airmail.cc> & Flavien Solt <flsolt@ethz.ch>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

// For all new cells, add src=cell->get_src_attribute()

#include "kernel/log.h"
#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/yosys.h"
#include "kernel/sigtools.h"

USING_YOSYS_NAMESPACE

extern bool is_signal_excluded(std::vector<string> *excluded_signals, string signal_name);
extern std::string get_wire_taint_idstring(RTLIL::IdString id_string, unsigned int taint_id);
extern std::vector<RTLIL::SigSpec> get_corresponding_taint_signals(RTLIL::Module *module, std::vector<string> *excluded_signals,
								   const RTLIL::SigSpec &sig, unsigned int num_taints);

// Power leakage tracking functions (new in Phase 1)
extern std::string get_wire_leakage_idstring(RTLIL::IdString id_string, unsigned int leakage_id);
extern std::vector<RTLIL::SigSpec> get_corresponding_leakage_signals(RTLIL::Module *module, std::vector<string> *excluded_signals,
									  const RTLIL::SigSpec &sig, unsigned int num_leakages);
extern bool is_clock_or_reset_signal(RTLIL::IdString signal_name);

// Power leakage handlers (new in Phase 2)
extern bool cellift_dff_with_leakage(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);

extern bool cellift_dlatch(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dlatch_en(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dff(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dff_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_adff(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdff(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdff_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_adffe(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdffe(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dffe(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dffe_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdffce(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdffce_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdffe_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dffe_rst_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sdff_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_dff_simple_techmap(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_add(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sub(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_not(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_neg(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_and(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_or(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_mul(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_pmux_large_cells(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_pmux_small_cells(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_mux(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_xor(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_eq_ne(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_ge(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_gt(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_le(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_lt(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_logic_and(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_logic_or(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_logic_not(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_reduce_and(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_reduce_xor(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shl_sshl_precise(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shl_sshl_imprecise(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shr_sshr_imprecise(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shr(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_sshr(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shift_shiftx_precise(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shiftx_imprecise(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_shift_imprecise(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);

extern bool cellift_conjunctive_one_input(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_conjunctive_two_inputs(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);
extern bool cellift_conjunctive_three_inputs(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints,
					     std::vector<string> *excluded_signals);

extern bool rtlift_add(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals);

PRIVATE_NAMESPACE_BEGIN

static RTLIL::SigSpec zero_extend_to_32(const RTLIL::SigSpec &sig)
{
	RTLIL::SigSpec out = sig;
	if (out.size() < 32)
		out.append(RTLIL::SigSpec(RTLIL::State::S0, 32 - out.size()));
	return out;
}

static RTLIL::SigSpec add_to_accum(RTLIL::Module *module, const RTLIL::SigSpec &accum, const RTLIL::SigSpec &addend)
{
	RTLIL::SigSpec acc32 = zero_extend_to_32(accum);
	RTLIL::SigSpec add32 = zero_extend_to_32(addend);
	return module->Add(NEW_ID, acc32, add32);
}

static RTLIL::SigSpec popcount_bits(RTLIL::Module *module, const RTLIL::SigSpec &bits)
{
	RTLIL::SigSpec acc = RTLIL::SigSpec(RTLIL::State::S0, 32);
	for (int i = 0; i < bits.size(); ++i) {
		RTLIL::SigSpec bit = bits.extract(i, 1);
		acc = add_to_accum(module, acc, bit);
	}
	return acc;
}

// General function to add HW/HD counters to any module
// This works for top modules as well as internal core modules
static void add_hw_hd_counters_to_module(RTLIL::Module *target_module, unsigned int num_taints, bool opt_verbose, bool is_top_module, bool opt_hd_taint_prev, const std::vector<std::string> &counter_include)
{
	if (opt_verbose)
		log("Adding HW/HD counters to module %s (is_top=%d)\n", target_module->name.c_str(), is_top_module);

	// Identify a clock and optional reset in the target module.
	//
	// This used to be a bare substring search for "clk"/"clock" over the input
	// ports, with no width check, taking the first hit in whatever order the
	// wire dict happened to yield. That is wrong in two ways, and both bite as
	// soon as the scope covers more than a hand-written wrapper:
	//
	//   * A WIDE port whose name merely CONTAINS the word. Rocket's
	//     `SystemBus` has an input called
	//     `auto_coupler_from_tile_tl_master_clock_xing_in_a_bits_address` --
	//     a TileLink address bus. The old code selected it as the clock and
	//     the pass aborted in rtlil.cc's cell checker, because a $dff CLK
	//     must be one bit. A clock or reset is a single bit, always, so
	//     requiring width == 1 is both correct and sufficient to exclude this
	//     whole class.
	//   * Non-determinism. `wires_` is a dict, so "first match" is not a
	//     stable choice when several ports match. Score every candidate and
	//     break ties on the name, so the same netlist always gets the same
	//     clock.
	//
	// Scores, highest wins: an exact conventional name, then one ending in
	// the word (`..._clk`, `..._clock`), then a bare containment as the last
	// resort. `clk_i`/`rst_ni` keep their historical precedence so existing
	// designs select exactly the wire they selected before.
	RTLIL::Wire *clk_wire = nullptr;
	RTLIL::Wire *rst_wire = nullptr;
	{
		int best_clk = 0, best_rst = 0;
		auto ends_with = [](const std::string &h, const std::string &t) {
			return h.size() >= t.size() && h.compare(h.size() - t.size(), t.size(), t) == 0;
		};
		for (auto &wire_it : target_module->wires_) {
			RTLIL::Wire *w = wire_it.second;
			if (!w->port_input)
				continue;
			// A clock or a reset is one bit. This is the check whose absence
			// let a TileLink address bus be chosen as a clock.
			if (w->width != 1)
				continue;
			std::string n = w->name.str();
			// Skip taint/leakage variants when selecting clocks/resets.
			if (n.find("_t0") != std::string::npos || n.find("_leak") != std::string::npos)
				continue;

			int cs = 0;
			if (n == "\\clk_i")                              cs = 5;
			else if (n == "\\clk" || n == "\\clock")        cs = 4;
			else if (ends_with(n, "_clk") || ends_with(n, "_clock")) cs = 3;
			else if (n.find("clk_i") != std::string::npos)     cs = 2;
			else if (n.find("clk") != std::string::npos ||
			         n.find("clock") != std::string::npos)     cs = 1;
			if (cs > best_clk || (cs == best_clk && cs > 0 && clk_wire &&
			                      n < clk_wire->name.str())) {
				best_clk = cs;
				clk_wire = w;
			}

			int rs = 0;
			if (n == "\\rst_ni")                              rs = 5;
			else if (n == "\\rst" || n == "\\reset" ||
			         n == "\\rst_n" || n == "\\resetn")      rs = 4;
			else if (ends_with(n, "_rst") || ends_with(n, "_reset") ||
			         ends_with(n, "_rst_n") || ends_with(n, "_resetn")) rs = 3;
			else if (n.find("rst") != std::string::npos ||
			         n.find("reset") != std::string::npos)      rs = 1;
			if (rs > best_rst || (rs == best_rst && rs > 0 && rst_wire &&
			                      n < rst_wire->name.str())) {
				best_rst = rs;
				rst_wire = w;
			}
		}
	}

	if (!clk_wire && opt_verbose)
		log("  Warning: No clock input found in module %s; leakage counters will not be registered.\n", target_module->name.c_str());

	// Build dictionary of data wires (excluding taint and leakage signals)
	dict<std::string, RTLIL::Wire *> data_wires;
	dict<std::string, RTLIL::Wire *> prev_wires;
	// Registered taint, for the HD gate below. Keyed by the TAINT wire's name,
	// not the base name: the data flop is shared across taint labels, a taint
	// flop is per label.
	dict<std::string, RTLIL::Wire *> prev_taint_wires;
	for (auto &wire_it : target_module->wires_) {
		RTLIL::Wire *w = wire_it.second;
		std::string n = w->name.str();
		if (n.find("_t") != std::string::npos || n.find("_leak") != std::string::npos)
			continue;
		if (is_clock_or_reset_signal(w->name))
			continue;
		data_wires[n] = w;
	}

	// Create HW/HD counters for each taint label
	for (unsigned int taint_id = 0; taint_id < num_taints; ++taint_id) {
		std::string taint_suffix = "_t" + std::to_string(taint_id);
		RTLIL::SigSpec hw_bits;
		RTLIL::SigSpec hd_bits;

		// Snapshot the wire list before touching it. The body below calls
		// addWire (the _prev_hw_hd flops), which inserts into wires_ and can
		// rehash it, and iterating a container while inserting into it is
		// undefined. The pre-existing code did exactly that with one insertion
		// per pair; gating HD on the registered taint adds a second, so take
		// the snapshot rather than widen the window.
		std::vector<RTLIL::Wire *> candidate_wires;
		candidate_wires.reserve(target_module->wires_.size());
		for (auto &wire_it : target_module->wires_)
			candidate_wires.push_back(wire_it.second);

		// Iterate through all wires in the target module, looking for tainted signals
		for (RTLIL::Wire *taint_wire : candidate_wires) {
			std::string tn = taint_wire->name.str();
			
			// Check if this is a taint signal (ends with _t<id>)
			if (tn.size() <= taint_suffix.size())
				continue;
			if (tn.find(taint_suffix) == std::string::npos)
				continue;
			if (tn.compare(tn.size() - taint_suffix.size(), taint_suffix.size(), taint_suffix) != 0)
				continue;
			
			// Find the corresponding data wire
			std::string base_name = tn.substr(0, tn.size() - taint_suffix.size());
			auto it = data_wires.find(base_name);
			if (it == data_wires.end())
				continue;
			RTLIL::Wire *data_wire = it->second;

			// Optional allowlist, restricting which wires feed the COUNTERS.
			// Taint propagation is untouched -- this only narrows the HW/HD
			// aggregation.
			//
			// Why this exists: popcount_bits() sums the tainted bits with one
			// 32-bit adder PER BIT, chained serially, so the simulator's cost
			// scales with the total instrumented bit count. A flattened Ibex
			// reaches 16029 tainted bits, i.e. ~32000 chained 32-bit adders
			// across the two counters, and a single 30k-cycle trace then takes
			// over 17 minutes against seconds unflattened. Flattening is what
			// makes the core's internals visible at all (unflattened, only the
			// wrapper's 31 memory-boundary wires are instrumented), so the way
			// out is to flatten AND name the few nets under investigation:
			// an allowlist of "register_file_i" is ~1160 bits instead of 16029.
			if (!counter_include.empty()) {
				bool wanted = false;
				for (const std::string &pat : counter_include)
					if (base_name.find(pat) != std::string::npos) { wanted = true; break; }
				if (!wanted)
					continue;
			}

			// HW: AND(data, taint) for each bit
			RTLIL::SigSpec data_sig(data_wire);
			RTLIL::SigSpec taint_sig(taint_wire);
			RTLIL::SigSpec and_sig = target_module->And(NEW_ID, data_sig, taint_sig);
			hw_bits.append(and_sig);

			// HD: XOR(data, data_prev) AND taint for each bit
			if (clk_wire) {
				RTLIL::Wire *prev_wire = nullptr;
				auto prev_it = prev_wires.find(base_name);
				if (prev_it != prev_wires.end()) {
					prev_wire = prev_it->second;
				} else {
					std::string prev_name = base_name + "_prev_hw_hd";
					prev_wire = target_module->addWire(RTLIL::escape_id(prev_name), data_wire->width);
					target_module->addDff(NEW_ID, RTLIL::SigSpec(clk_wire), data_sig, RTLIL::SigSpec(prev_wire));
					prev_wires[base_name] = prev_wire;
				}
				RTLIL::SigSpec xor_sig = target_module->Xor(NEW_ID, data_sig, RTLIL::SigSpec(prev_wire));

				// The gate on the transition. Plainly `& taint` scores a
				// transition only if the value is tainted in the CURRENT cycle,
				// which silently drops the case where a tainted value is
				// overwritten by an untainted one. That case is not exotic: it
				// is Gigerl et al.'s C2 ("a register holding one share must not
				// be overwritten with its counterpart"), the commonest masking
				// implementation bug, and the counterpart is untainted whenever
				// the taint source is one share only -- which is how every
				// scenario in this tree is configured. The transition is
				// physically key-dependent (it toggles by HW(share0 ^ share1) =
				// HW of the true value) and the model reports exactly 0.00 for
				// it. Measured on Ibex: HD is identically zero in both groups over
				// 400 traces, although the transition at those cycles is
				// key-dependent by construction.
				//
				// `| taint_prev` fixes that: a transition counts if a tainted
				// value took part in it, at either end. HW is untouched.
				//
				// KEEP THIS OFF unless you know why you want it. It is an
				// over-approximation, but an over-approximation that INVENTS
				// STRUCTURE, which is worse than useless for attribution --
				// SPARC's whole purpose. Measured on Ibex masked AES with the
				// register file instrumented, N=60/group, fixed-vs-random key:
				//
				//   gate            HD leaky cycles   max |t|
				//   taint            7 (key schedule)   7.05
				//   taint|taint_prev 12                20.09
				//
				// The five extra cycles formed a clean 1694-cycle grid -- one
				// per AES round, zero drift -- attributing to AddRoundKey's
				// state[i] ^= rk_share[i]. It looks exactly like a real
				// round-periodic leak and it is not: with the strict gate it
				// vanishes entirely. The cause is that `taint | taint_prev`
				// counts a transition whose endpoints are tainted in DIFFERENT
				// cycles, so a register reloaded with fresh tainted data every
				// iteration fires once per round at fixed phase. The surviving
				// 7 cycles are the real residual, and they attribute to
				// aes128_sw_masktable.c:383-386.
				//
				// So it does not merely rescale HD, it changes which cycles
				// are flagged and would have to be re-validated against
				// silicon before it could ever be a default.
				RTLIL::SigSpec hd_gate = taint_sig;
				if (opt_hd_taint_prev) {
					RTLIL::Wire *prev_taint = nullptr;
					auto pt_it = prev_taint_wires.find(tn);
					if (pt_it != prev_taint_wires.end()) {
						prev_taint = pt_it->second;
					} else {
						std::string pt_name = base_name + taint_suffix + "_prev_hw_hd";
						prev_taint = target_module->addWire(RTLIL::escape_id(pt_name), taint_wire->width);
						target_module->addDff(NEW_ID, RTLIL::SigSpec(clk_wire), taint_sig, RTLIL::SigSpec(prev_taint));
						prev_taint_wires[tn] = prev_taint;
					}
					hd_gate = target_module->Or(NEW_ID, taint_sig, RTLIL::SigSpec(prev_taint));
				}
				RTLIL::SigSpec hd_and = target_module->And(NEW_ID, xor_sig, hd_gate);
				hd_bits.append(hd_and);
			}
		}

		// Create HW counter output
		if (hw_bits.size() > 0) {
			std::string hw_name = "hamming_weight_counter_t" + std::to_string(taint_id);
			RTLIL::Wire *hw_out = target_module->wire(RTLIL::escape_id(hw_name));
			if (!hw_out) {
				hw_out = target_module->addWire(RTLIL::escape_id(hw_name), 32);
				hw_out->port_output = true;
			}
			RTLIL::SigSpec hw_count = popcount_bits(target_module, hw_bits);
			if (clk_wire) {
				RTLIL::Wire *hw_reg = target_module->addWire(NEW_ID, 32);
				target_module->addDff(NEW_ID, RTLIL::SigSpec(clk_wire), hw_count, RTLIL::SigSpec(hw_reg));
				target_module->connect(hw_out, hw_reg);
			} else {
				target_module->connect(hw_out, hw_count);
			}
			if (opt_verbose)
				log("  Created HW counter for taint %d: %d tainted bits\n", taint_id, hw_bits.size());
		} else if (opt_verbose) {
			log("  Warning: No tainted signals found for taint %d in module %s\n", taint_id, target_module->name.c_str());
		}

		// Create HD counter output
		if (hd_bits.size() > 0) {
			std::string hd_name = "hamming_distance_counter_t" + std::to_string(taint_id);
			RTLIL::Wire *hd_out = target_module->wire(RTLIL::escape_id(hd_name));
			if (!hd_out) {
				hd_out = target_module->addWire(RTLIL::escape_id(hd_name), 32);
				hd_out->port_output = true;
			}
			RTLIL::SigSpec hd_count = popcount_bits(target_module, hd_bits);
			if (clk_wire) {
				RTLIL::Wire *hd_reg = target_module->addWire(NEW_ID, 32);
				target_module->addDff(NEW_ID, RTLIL::SigSpec(clk_wire), hd_count, RTLIL::SigSpec(hd_reg));
				target_module->connect(hd_out, hd_reg);
			} else {
				target_module->connect(hd_out, hd_count);
			}
			if (opt_verbose)
				log("  Created HD counter for taint %d: %d tainted transition bits\n", taint_id, hd_bits.size());
		}
	}

	target_module->fixup_ports();
}

// ---------------------------------------------------------------------------
// Hierarchical counter aggregation.
//
// The previous implementation (promote_counters_hierarchically) created a
// per-instance wire in the parent and connected the child's counter port to
// it -- and stopped. It never summed the per-instance wires, never drove a
// counter output on the parent, and never recursed toward the top, so every
// promoted wire dangled and `opt -purge` reclaimed it. That is why
// -power-leakage-auto-scope never produced a usable counter, and why
// instrumenting a deep module (a register file, say) yielded nothing at the
// top: the counters existed, but nothing added them up.
//
// This walks the instantiation DAG in post-order (children finished before
// their parents) and drives each module's counter output with
//
//     its own local counter, if it has one  +  the sum over its instances
//
// The sum is deliberately COMBINATIONAL. Every contributing counter is already
// registered once at the level that produced it, so adding a register per
// hierarchy level would skew deeper modules by one cycle per level and
// misalign the per-cycle trace the whole TVLA flow rests on.
// ---------------------------------------------------------------------------

static void aggregate_counters_in_module(RTLIL::Design *design, RTLIL::Module *mod,
                                         unsigned int num_taints, bool opt_verbose,
                                         pool<RTLIL::Module *> &done)
{
	if (!mod || done.count(mod))
		return;
	done.insert(mod);

	// Children first.
	for (auto cell : mod->cells()) {
		RTLIL::Module *sub = design->module(cell->type);
		if (sub)
			aggregate_counters_in_module(design, sub, num_taints, opt_verbose, done);
	}

	static const char *kinds[2] = { "hamming_weight", "hamming_distance" };

	for (unsigned int taint_id = 0; taint_id < num_taints; ++taint_id) {
		for (int k = 0; k < 2; ++k) {
			std::string pname = std::string(kinds[k]) + "_counter_t" + std::to_string(taint_id);
			RTLIL::IdString pid = RTLIL::escape_id(pname);

			// One term per instantiated child that exposes this counter.
			std::vector<RTLIL::SigSpec> terms;
			for (auto cell : mod->cells()) {
				RTLIL::Module *sub = design->module(cell->type);
				if (!sub)
					continue;
				RTLIL::Wire *sub_port = sub->wire(pid);
				if (!sub_port || !sub_port->port_output)
					continue;

				std::string rn = RTLIL::unescape_id(cell->name) + "_" + pname;
				RTLIL::IdString rid = RTLIL::escape_id(rn);
				RTLIL::Wire *recv = mod->wire(rid);
				if (!recv)
					recv = mod->addWire(rid, 32);
				cell->setPort(pid, RTLIL::SigSpec(recv));
				terms.push_back(RTLIL::SigSpec(recv));
			}

			if (terms.empty())
				continue;

			// If this module already has its own counter output, take over its
			// driver so the local contribution becomes one more term, rather
			// than being overwritten by the children's sum.
			RTLIL::Wire *port = mod->wire(pid);
			RTLIL::SigSpec local;
			bool has_local = false;
			if (port) {
				for (auto it = mod->connections_.begin(); it != mod->connections_.end(); ++it) {
					if (it->first == RTLIL::SigSpec(port)) {
						local = it->second;
						mod->connections_.erase(it);
						has_local = true;
						break;
					}
				}
			} else {
				port = mod->addWire(pid, 32);
			}
			port->port_output = true;

			RTLIL::SigSpec total = has_local ? zero_extend_to_32(local)
			                                 : RTLIL::SigSpec(RTLIL::State::S0, 32);
			for (auto &t : terms)
				total = add_to_accum(mod, total, t);

			mod->connect(RTLIL::SigSpec(port), total);

			if (opt_verbose)
				log("  %s: %d instance counter(s)%s -> %s\n", mod->name.c_str(),
				    (int)terms.size(), has_local ? " + local" : "", pname.c_str());
		}
	}

	mod->fixup_ports();
}

static void aggregate_counters_bottom_up(RTLIL::Design *design, RTLIL::Module *top_module,
                                         unsigned int num_taints, bool opt_verbose)
{
	if (opt_verbose)
		log("Aggregating HW/HD counters bottom-up from %s\n", top_module->name.c_str());
	pool<RTLIL::Module *> done;
	aggregate_counters_in_module(design, top_module, num_taints, opt_verbose, done);
}

// Auto-detect modules that contain tainted signals
static std::vector<RTLIL::Module*> detect_tainted_modules(RTLIL::Design *design, bool opt_verbose)
{
	std::vector<RTLIL::Module*> tainted_modules;
	
	for (auto module : design->modules()) {
		// Skip Yosys internal modules
		if (module->name.begins_with("\\$"))
			continue;
		
		// Check if module has any tainted signals
		bool has_taint = false;
		for (auto &wire_it : module->wires_) {
			std::string wire_name = wire_it.second->name.str();
			if (wire_name.find("_t0") != std::string::npos || wire_name.find("_t1") != std::string::npos) {
				has_taint = true;
				break;
			}
		}
		
		if (has_taint) {
			tainted_modules.push_back(module);
			if (opt_verbose)
				log("Auto-detected tainted module: %s\n", module->name.c_str());
		}
	}
	
	return tainted_modules;
}

// Find modules by base name, handling $paramod prefixes and wildcards
static std::vector<RTLIL::Module*> find_modules_by_name(RTLIL::Design *design, const std::string &base_name, bool opt_verbose)
{
	std::vector<RTLIL::Module*> found_modules;
	
	// First try exact match (with backslash prefix)
	RTLIL::IdString exact_id = RTLIL::escape_id(base_name);
	RTLIL::Module *exact_match = design->module(exact_id);
	if (exact_match) {
		found_modules.push_back(exact_match);
		if (opt_verbose)
			log("    Found exact match: %s\n", base_name.c_str());
		return found_modules;
	}
	
	// If no exact match, search for modules with matching base name
	// This handles $paramod$HASH\base_name format
	std::string search_pattern = base_name;
	if (search_pattern[0] == '\\')
		search_pattern = search_pattern.substr(1);  // Remove backslash for pattern matching
	
	for (auto module : design->modules()) {
		std::string mod_name = module->name.str();
		
		// Check if module name ends with our search pattern
		// This catches $paramod$HASH\cellift_ibex_core when searching for cellift_ibex_core
		if (mod_name.find("\\" + search_pattern) != std::string::npos) {
			found_modules.push_back(module);
			if (opt_verbose)
				log("    Found parametrized match: %s (searched for %s)\n", mod_name.c_str(), base_name.c_str());
		}
	}
	
	return found_modules;
}

struct CellIFTWorker {
      private:
	// Command line arguments.
	bool opt_verbose = false;
	bool opt_rtlift = false;		     // Whether to implement the adder/multiplier using the RTLIFT fashion.
	bool opt_track_power_leakage = false;	     // Phase 2: Enable power side-channel leakage tracking.
	pool<string> opt_conjunctive_cells_pool;     // Whether to implement over-conservatively with plain OR gates.
	bool opt_conjunctive_gates = false;	     // Whether to implement over-conservatively with plain OR gates.
	bool opt_precise_shiftx = false;	     // Whether to implement precise IFT logic for the shiftx.
	bool opt_imprecise_shl_sshl = false;	     // Whether to implement precise IFT logic for the shl and sshl.
	bool opt_imprecise_shr_sshr = false;	     // Whether to implement precise IFT logic for the shr and sshr.
	bool opt_pmux_use_large_cells = false;	     // pmux instrumentation performance.
	unsigned int num_taints = 1;
	std::vector<string> *excluded_signals;

	RTLIL::Module *module = nullptr;
	const RTLIL::IdString cellift_attribute_name = ID(cellift);

	void create_cellift_logic()
	{
		// If cellift has already been applied.
		if (module->get_bool_attribute(cellift_attribute_name)) {
			log("CellIFT has already been applied to module %s. Aborting CellIFT instrumentation.\n", module->name.c_str());
			return;
		}
		if (opt_verbose)
			log("CellIFTing module %s.\n", module->name.c_str());

		std::vector<RTLIL::SigSig> connections(module->connections());

		// Add the new taint I/O connections.
		pool<std::pair<RTLIL::IdString, int>> input_wires_to_add;
		pool<std::pair<RTLIL::IdString, int>> output_wires_to_add;

		// First, create the input and output wires for the taints if they are not excluded.
		for (auto &wire_it : module->wires_) {
			// If this is a module port corresponding to a non-excluded taint signal, then add the corresponding taint signal ports.
			if (wire_it.second->port_input && !is_signal_excluded(excluded_signals, wire_it.first.str())) {
				for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
					input_wires_to_add.insert(
					  std::pair<RTLIL::IdString, int>(get_wire_taint_idstring(wire_it.first, taint_id), wire_it.second->width));
				}
			}
			// All output ports must be augmented (excluded or not).
			if (wire_it.second->port_output && !is_signal_excluded(excluded_signals, wire_it.first.str())) {
				for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
					output_wires_to_add.insert(
					  std::pair<RTLIL::IdString, int>(get_wire_taint_idstring(wire_it.first, taint_id), wire_it.second->width));
				}
			}
		}
		// No need to check for taint signal exclusion here, the filtering has already been made when adding the signals to the
		// *put_wires_to_add pools.
		for (auto &wire_info_it : input_wires_to_add) {
			if (opt_verbose)
				log("New input wire: %s.\n", wire_info_it.first.c_str());
			RTLIL::Wire *w = module->addWire(wire_info_it.first, wire_info_it.second);
			w->port_input = true;
		}
		for (auto &wire_info_it : output_wires_to_add) {
			if (opt_verbose)
				log("New output wire: %s.\n", wire_info_it.first.c_str());
			RTLIL::Wire *w = module->addWire(wire_info_it.first, wire_info_it.second);
			w->port_output = true;
		}

		// NEW: Create leakage output ports (Stage 1 for leakage)
		// This mirrors the taint port creation mechanism for leakage signals
		if (opt_track_power_leakage) {
			pool<std::pair<RTLIL::IdString, int>> leakage_output_wires_to_add;
			
			// Collect all output signals that should have leakage tracking
			for (auto &wire_it : module->wires_) {
				if (wire_it.second->port_output && !is_signal_excluded(excluded_signals, wire_it.first.str())) {
					for (unsigned int leakage_id = 0; leakage_id < num_taints; leakage_id++) {
						leakage_output_wires_to_add.insert(
							std::pair<RTLIL::IdString, int>(
								get_wire_leakage_idstring(wire_it.first, leakage_id),
								wire_it.second->width
							)
						);
					}
				}
			}
			
			// Create the leakage output port wires and mark them as visible
			for (auto &wire_info_it : leakage_output_wires_to_add) {
				if (opt_verbose)
					log("New leakage output wire: %s.\n", wire_info_it.first.c_str());
				RTLIL::Wire *w = module->addWire(wire_info_it.first, wire_info_it.second);
				w->port_output = true;  // KEY: Make visible as module port!
			}
		}

		// True: the cell will be SUPPLEMENTED by the taint tracking logic.
		// False: the cell will be REPLACED by the taint tracking logic.
		bool keep_current_cell;

		// Structures to make the modifications once the iteration through all the cells is complete.
		std::vector<Yosys::RTLIL::Cell *> original_cells = module->cells().to_vector();
		std::vector<Yosys::RTLIL::Cell *> cells_to_remove;

		// Second, add the logic corresponding to the cells. The input and output ports are supposed to have a width of 1. The corresponding
		// port of the input port is obtained
		for (auto &cell : original_cells) {
			if (opt_verbose)
				log("    CellIFTing %s cell (%s)\n", cell->type.c_str(), cell->name.c_str());

			// By default, do not remove the original cell but supplement it with IFT logic.
			keep_current_cell = true;

			////
			// Latches
			////

			if (cell->type.in(ID($dlatch)))
				keep_current_cell = cellift_dlatch(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($_DLATCH_N_), ID($_DLATCH_P_)))
				keep_current_cell = cellift_dlatch_en(module, cell, num_taints, excluded_signals);

			////
			// Flip-flops
			////

			else if (cell->type.in(ID($dff))) {
				if (opt_track_power_leakage)
					keep_current_cell = cellift_dff_with_leakage(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_dff(module, cell, num_taints, excluded_signals);
			}

			else if (cell->type.in(ID($_DFF_NN0_), ID($_DFF_NN1_), ID($_DFF_NP0_), ID($_DFF_NP1_), ID($_DFF_PN0_), ID($_DFF_PN1_),
					       ID($_DFF_PP0_), ID($_DFF_PP0_)))
				keep_current_cell = cellift_dff_techmap(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($adff)))
				keep_current_cell = cellift_adff(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($sdff)))
				keep_current_cell = cellift_sdff(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($_SDFF_NN0_), ID($_SDFF_NN1_), ID($_SDFF_NP0_), ID($_SDFF_NP1_), ID($_SDFF_PN0_), ID($_SDFF_PN1_),
					       ID($_SDFF_PP0_), ID($_SDFF_PP1_)))
				keep_current_cell = cellift_sdff_techmap(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($adffe)))
				keep_current_cell = cellift_adffe(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($sdffe)))
				keep_current_cell = cellift_sdffe(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($dffe)))
				keep_current_cell = cellift_dffe(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($_DFFE_NN_), ID($_DFFE_NP_), ID($_DFFE_PN_), ID($_DFFE_PP_)))
				keep_current_cell = cellift_dffe_techmap(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($sdffce)))
				keep_current_cell = cellift_sdffce(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($_SDFFCE_NN0N_), ID($_SDFFCE_NN0P_), ID($_SDFFCE_NN1N_), ID($_SDFFCE_NN1P_), ID($_SDFFCE_NP0N_),
					       ID($_SDFFCE_NP0P_), ID($_SDFFCE_NP1N_), ID($_SDFFCE_NP1P_), ID($_SDFFCE_PN0N_), ID($_SDFFCE_PN0P_),
					       ID($_SDFFCE_PN1N_), ID($_SDFFCE_PN1P_), ID($_SDFFCE_PP0N_), ID($_SDFFCE_PP0P_), ID($_SDFFCE_PP1N_),
					       ID($_SDFFCE_PP1P_)))
				keep_current_cell = cellift_sdffce_techmap(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($_SDFFE_NN0N_), ID($_SDFFE_NN0P_), ID($_SDFFE_NN1N_), ID($_SDFFE_NN1P_), ID($_SDFFE_NP0N_),
					       ID($_SDFFE_NP0P_), ID($_SDFFE_NP1N_), ID($_SDFFE_NP1P_), ID($_SDFFE_PN0N_), ID($_SDFFE_PN0P_),
					       ID($_SDFFE_PN1N_), ID($_SDFFE_PN1P_), ID($_SDFFE_PP0N_), ID($_SDFFE_PP0P_), ID($_SDFFE_PP1N_),
					       ID($_SDFFE_PP1P_)))
				keep_current_cell = cellift_sdffe_techmap(module, cell, num_taints, excluded_signals);
			else if (cell->type.in(ID($_DFFE_NN0N_), ID($_DFFE_NN0P_), ID($_DFFE_NN1N_), ID($_DFFE_NN1P_), ID($_DFFE_NP0N_),
					       ID($_DFFE_NP0P_), ID($_DFFE_NP1N_), ID($_DFFE_NP1P_), ID($_DFFE_PN0N_), ID($_DFFE_PN0P_),
					       ID($_DFFE_PN1N_), ID($_DFFE_PN1P_), ID($_DFFE_PP0N_), ID($_DFFE_PP0P_), ID($_DFFE_PP1N_),
					       ID($_DFFE_PP1P_)))
				keep_current_cell = cellift_dffe_rst_techmap(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($_SDFF_PN0_), ID($_SDFF_PN1_), ID($_SDFF_PP0_)))
				keep_current_cell = cellift_sdff_techmap(module, cell, num_taints, excluded_signals);
			else if (cell->type.in(ID($_DFF_N_), ID($_DFF_P_)))
				keep_current_cell = cellift_dff_simple_techmap(module, cell, num_taints, excluded_signals);

			////
			// Stateless cells
			////

			else if (cell->type.in(ID($add)))
				if (opt_conjunctive_cells_pool.find("add") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else if (opt_rtlift)
					keep_current_cell = rtlift_add(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_add(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($sub)))
				if (opt_conjunctive_cells_pool.find("sub") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_sub(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($not), ID($_NOT_)))
				keep_current_cell = cellift_not(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($neg)))
				if (opt_conjunctive_cells_pool.find("neg") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_one_input(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_neg(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($and), ID($_AND_), ID($_NAND_)))
				if (opt_conjunctive_cells_pool.find("and") != opt_conjunctive_cells_pool.end() || opt_conjunctive_gates)
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_and(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($or), ID($_OR_), ID($_NOR_)))
				if (opt_conjunctive_cells_pool.find("or") != opt_conjunctive_cells_pool.end() || opt_conjunctive_gates)
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_or(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($pmux)))
				if (opt_conjunctive_cells_pool.find("pmux") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_three_inputs(module, cell, num_taints, excluded_signals);
				else if (opt_pmux_use_large_cells)
					keep_current_cell = cellift_pmux_large_cells(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_pmux_small_cells(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($mux), ID($_MUX_), ID($_NMUX_)))
				if (opt_conjunctive_cells_pool.find("mux") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_three_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_mux(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($xor), ID($_XOR_), ID($_XNOR_)))
				keep_current_cell = cellift_xor(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($eq), ID($ne)))
				if (opt_conjunctive_cells_pool.find("eq-ne") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_eq_ne(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($ge)))
				if (opt_conjunctive_cells_pool.find("ge") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_ge(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($gt)))
				if (opt_conjunctive_cells_pool.find("gt") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_gt(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($le)))
				if (opt_conjunctive_cells_pool.find("le") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_le(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($lt)))
				if (opt_conjunctive_cells_pool.find("lt") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_lt(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($logic_and)))
				if (opt_conjunctive_cells_pool.find("logic-and") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_logic_and(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($logic_or)))
				if (opt_conjunctive_cells_pool.find("logic-or") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_logic_or(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($logic_not), ID($reduce_or), ID($reduce_bool)))
				if (opt_conjunctive_cells_pool.find("logic-not") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_one_input(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_logic_not(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($reduce_and)))
				if (opt_conjunctive_cells_pool.find("reduce-and") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_one_input(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_reduce_and(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($reduce_xor)))
				keep_current_cell = cellift_reduce_xor(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($shl), ID($sshl)))
				if (opt_conjunctive_cells_pool.find("shl-sshl") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else if (opt_imprecise_shl_sshl)
					keep_current_cell = cellift_shl_sshl_imprecise(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_shl_sshl_precise(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($shr)))
				if (opt_conjunctive_cells_pool.find("shr") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else if (opt_imprecise_shr_sshr)
					keep_current_cell = cellift_shr_sshr_imprecise(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_shr(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($sshr)))
				if (opt_conjunctive_cells_pool.find("sshr") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else if (opt_imprecise_shr_sshr)
					keep_current_cell = cellift_shr_sshr_imprecise(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_sshr(module, cell, num_taints, excluded_signals);

			else if ((cell->type.in(ID($shift)) && opt_precise_shiftx) || (cell->type.in(ID($shiftx)) && opt_precise_shiftx))
				if (opt_conjunctive_cells_pool.find("shift-shiftx") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_shift_shiftx_precise(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($shiftx)) && !opt_precise_shiftx)
				if (opt_conjunctive_cells_pool.find("shift-shiftx") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_shiftx_imprecise(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($shift)) && !opt_precise_shiftx)
				if (opt_conjunctive_cells_pool.find("shift-shiftx") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_shift_imprecise(module, cell, num_taints, excluded_signals);

			else if (cell->type.in(ID($mul)))
				if (opt_conjunctive_cells_pool.find("mul") != opt_conjunctive_cells_pool.end())
					keep_current_cell = cellift_conjunctive_two_inputs(module, cell, num_taints, excluded_signals);
				else
					keep_current_cell = cellift_mul(module, cell, num_taints, excluded_signals);

			else if (module->design->module(cell->type) != nullptr) {
				// User cell type

				dict<RTLIL::IdString, RTLIL::SigSpec> orig_ports = cell->connections();
				for (auto &it : orig_ports) {
					RTLIL::SigSpec connected_sig = it.second;

					// Not the IFT-excluded signals.
					if (is_signal_excluded(excluded_signals, it.first.str()) ||
					    (it.second.is_wire() && is_signal_excluded(excluded_signals, it.second.as_wire()->name.str())))
						continue;

					std::vector<RTLIL::SigSpec> port_taints =
					  get_corresponding_taint_signals(module, excluded_signals, connected_sig, num_taints);
					for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
						cell->setPort(get_wire_taint_idstring(it.first.c_str(), taint_id), port_taints[taint_id]);
					}

					// NEW: Connect leakage ports for hierarchical propagation (only for output ports)
					if (opt_track_power_leakage) {
						// Check if this port is an output port in the submodule
						RTLIL::Module *submodule = module->design->module(cell->type);
						RTLIL::Wire *port_wire = submodule->wire(it.first);
						if (port_wire && port_wire->port_output) {
							std::vector<RTLIL::SigSpec> port_leakages =
							  get_corresponding_leakage_signals(module, excluded_signals, connected_sig, num_taints);
							for (unsigned int leakage_id = 0; leakage_id < num_taints; leakage_id++) {
								cell->setPort(get_wire_leakage_idstring(it.first.c_str(), leakage_id), port_leakages[leakage_id]);
							}
						}
					}
				}
			} else
				log_cmd_error("Cell type not supported: %s. Consider running techmap or creating your own IFT implementation.\n",
					      cell->type.c_str());

			if (!keep_current_cell)
				cells_to_remove.push_back(cell);
		} // end foreach cell in cells

		// Remove the cells that are replaced by the IFT compound.
		for (RTLIL::Cell *cell_to_remove : cells_to_remove)
			module->remove(cell_to_remove);

		if (module->processes.size())
			log_error("Unexpected process. Cellift requires a `proc` pass before.\n");

		// For all original connections, also connect the corresponding taints.
		for (auto &conn : connections) {
			log_assert(conn.first.size() == conn.second.size());

			std::vector<RTLIL::SigSpec> first = get_corresponding_taint_signals(module, excluded_signals, conn.first, num_taints);
			std::vector<RTLIL::SigSpec> second = get_corresponding_taint_signals(module, excluded_signals, conn.second, num_taints);

			for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++)
				module->connect(first[taint_id], second[taint_id]);
		}

		// NEW: For all original connections, also connect the corresponding leakages.
		if (opt_track_power_leakage) {
			for (auto &conn : connections) {
				log_assert(conn.first.size() == conn.second.size());

				std::vector<RTLIL::SigSpec> first = get_corresponding_leakage_signals(module, excluded_signals, conn.first, num_taints);
				std::vector<RTLIL::SigSpec> second = get_corresponding_leakage_signals(module, excluded_signals, conn.second, num_taints);

				for (unsigned int leakage_id = 0; leakage_id < num_taints; leakage_id++)
					module->connect(first[leakage_id], second[leakage_id]);
			}
		}

		// Connect taints for internal wires that are aliases of input ports.
		SigMap sigmap(module);
		dict<std::string, RTLIL::Wire *> input_by_key;
		for (auto &wire_it : module->wires_) {
			RTLIL::Wire *w = wire_it.second;
			if (!w->port_input)
				continue;
			if (is_signal_excluded(excluded_signals, w->name.str()))
				continue;
			std::string key = log_signal(sigmap(RTLIL::SigSpec(w)));
			input_by_key[key] = w;
		}
		for (auto &wire_it : module->wires_) {
			RTLIL::Wire *w = wire_it.second;
			if (w->port_input || w->port_output)
				continue;
			if (is_signal_excluded(excluded_signals, w->name.str()))
				continue;
			std::string key = log_signal(sigmap(RTLIL::SigSpec(w)));
			auto it = input_by_key.find(key);
			if (it == input_by_key.end())
				continue;

			RTLIL::SigSpec src = RTLIL::SigSpec(it->second);
			RTLIL::SigSpec dst = RTLIL::SigSpec(w);
			std::vector<RTLIL::SigSpec> src_taints =
				get_corresponding_taint_signals(module, excluded_signals, src, num_taints);
			std::vector<RTLIL::SigSpec> dst_taints =
				get_corresponding_taint_signals(module, excluded_signals, dst, num_taints);

			for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++)
				module->connect(dst_taints[taint_id], src_taints[taint_id]);
		}

		// Phase 3: Explicit handler for buffer input wires driven by module inputs
		// Connect TilePRCIDomain inputs directly to buffer_auto_in_0_* internal wires
		// This covers the case where Chisel/RTL infrastructure wires don't get connected
		// by default module input matching logic
		if (module->name == ID(TilePRCIDomain)) {
			std::vector<std::pair<std::string, std::string>> explicit_connections = {
				{"buffer_auto_in_0_a_ready_t0", "auto_tl_master_clock_xing_out_0_a_ready_t0"},
				{"buffer_auto_in_0_d_bits_corrupt_t0", "auto_tl_master_clock_xing_out_0_d_bits_corrupt_t0"},
				{"buffer_auto_in_0_d_bits_data_t0", "auto_tl_master_clock_xing_out_0_d_bits_data_t0"},
				{"buffer_auto_in_0_d_bits_denied_t0", "auto_tl_master_clock_xing_out_0_d_bits_denied_t0"},
				{"buffer_auto_in_0_d_bits_opcode_t0", "auto_tl_master_clock_xing_out_0_d_bits_opcode_t0"},
				{"buffer_auto_in_0_d_bits_param_t0", "auto_tl_master_clock_xing_out_0_d_bits_param_t0"},
				{"buffer_auto_in_0_d_bits_sink_t0", "auto_tl_master_clock_xing_out_0_d_bits_sink_t0"},
				{"buffer_auto_in_0_d_bits_size_t0", "auto_tl_master_clock_xing_out_0_d_bits_size_t0"},
				{"buffer_auto_in_0_d_bits_source_t0", "auto_tl_master_clock_xing_out_0_d_bits_source_t0"},
				{"buffer_auto_in_0_d_valid_t0", "auto_tl_master_clock_xing_out_0_d_valid_t0"},
			};

			for (const auto &conn : explicit_connections) {
				RTLIL::Wire *dst_w = module->wire(RTLIL::escape_id(conn.first));
				RTLIL::Wire *src_w = module->wire(RTLIL::escape_id(conn.second));

				if (dst_w && src_w) {
					if (opt_verbose)
						log("  Phase 3: Connecting %s <- %s\n", conn.first.c_str(), conn.second.c_str());
					module->connect(RTLIL::SigSpec(dst_w), RTLIL::SigSpec(src_w));
				}
			}
		}

		module->fixup_ports();
		module->set_bool_attribute(cellift_attribute_name, true);
	}

      public:
	CellIFTWorker(RTLIL::Module *_module, bool _opt_verbose, bool _opt_rtlift, bool _opt_track_power_leakage, bool _opt_conjunctive_gates,
		      pool<string> _opt_conjunctive_cells_pool, bool _opt_precise_shiftx, bool _opt_imprecise_shl_sshl, bool _opt_imprecise_shr_sshr,
		      bool _opt_pmux_use_large_cells, int unsigned _num_taints,
		      std::vector<string> *_excluded_signals)
	{
		module = _module;
		opt_verbose = _opt_verbose;
		opt_rtlift = _opt_rtlift;
		opt_track_power_leakage = _opt_track_power_leakage;
		opt_conjunctive_gates = _opt_conjunctive_gates;
		opt_conjunctive_cells_pool = _opt_conjunctive_cells_pool;
		opt_precise_shiftx = _opt_precise_shiftx;
		opt_imprecise_shl_sshl = _opt_imprecise_shl_sshl;
		opt_imprecise_shr_sshr = _opt_imprecise_shr_sshr;
		opt_pmux_use_large_cells = _opt_pmux_use_large_cells;
		num_taints = _num_taints;
		excluded_signals = _excluded_signals;

		create_cellift_logic();
	}
};

struct CelliftPass : public Pass {
	CelliftPass() : Pass("cellift", "instrument modules using the CellIFT mechanism.") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    cellift <command> [options] [selection]\n");
		log("\n");
		log("Instruments the selected design with CellIFT.\n");
		log("All processes must be broken down into cells, for instance using the built-in yosys command: `proc`.\n");
		log("All $pmux cells must be broken down into $mux cells, for instance using the built-in yosys command: `pmuxtree`.\n");
		log("Multipliers are implemented using a single OR reduction.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("  -num-distinct-labels\n");
		log("    The number of distinct available labels. Each new label reproduces the taint \n");
		log("    propagation logic and storage one more time. Default: 1.\n");
		log("\n");
		log("  -rtlift\n");
		log("    Use the RTLIFT-style adders.\n");
		log("    CellIFT-style adders are equally precise but faster in simulation and result in a simpler model than RTLIFT.\n");
		log("\n");
		log("  -conjunctive-gates\n");
		log("    Use an OR cells of all inputs for elementary logic gates (AND and OR). Equivalent to: -conjunctive-and -conjunctive-or\n");
		log("\n");
		log("  -verbose\n");
		log("    Verbose mode.\n");
		log("\n");
		log("  -track-power-leakage\n");
		log("    Enable power side-channel leakage tracking (Phase 2 feature).\n");
		log("    Instruments flip-flops to track switching transitions on tainted paths.\n");
		log("    Creates additional '_leak' shadow signals for leakage analysis.\n");
		log("    Default: disabled (standard CellIFT behavior).\n");
		log("\n");
		log("  -power-leakage-scope <module_name>\n");
		log("    Specify which module(s) to aggregate HW/HD counters in (comma-separated).\n");
		log("    By default, counters are aggregated in the top module only.\n");
		log("    Use this when tainted signals are internal to a core module.\n");
		log("    Example: -power-leakage-scope cellift_ibex_core\n");
		log("    Example: -power-leakage-scope \"BoomCore,RocketCore\"\n");
		log("\n");
		log("  -power-leakage-auto-scope\n");
		log("    Automatically detect modules with tainted signals and aggregate counters there.\n");
		log("    Overrides -power-leakage-scope if both are specified.\n");
		log("    Recommended for designs where taint location is unknown.\n");
		log("\n");
		log("  -power-leakage-include-signals\n");
		log("    Comma-separated wire-name substrings. When given, ONLY matching wires\n");
		log("    contribute to the HW/HD counters; taint propagation is unaffected. The\n");
		log("    counters sum one 32-bit adder per tainted bit, chained, so simulation\n");
		log("    cost scales with the instrumented bit count -- a flattened CPU reaches\n");
		log("    ~16k bits and becomes impractically slow. Use this to flatten (which is\n");
		log("    what exposes a core's internals) while measuring only the nets under\n");
		log("    investigation.\n");
		log("\n");
		log("  -hd-taint-prev\n");
		log("    Gate the Hamming-distance counter on (taint | taint_prev) instead of the\n");
		log("    current cycle's taint alone, by registering the taint alongside the data.\n");
		log("    Without it, a tainted value overwritten by an UNTAINTED one scores zero,\n");
		log("    although that transition is key-dependent -- which is exactly a C2 share\n");
		log("    violation when the taint source is one share of a masked value. Strictly\n");
		log("    more conservative; the Hamming-weight counter is unaffected. Costs one\n");
		log("    flip-flop per instrumented wire pair.\n");
		log("\n");
		log("  -exclude-signals\n");
		log("    Exclude a list of signal names from the IFT. Typically, this comprises clock and reset signals.\n");
		log("    The list must be comma-separated and must contain no space.\n");
		log("    Example: -exclude-signals clk_i,rst_ni\n");
		log("\n");
		log("  -precise-shiftx\n");
		log("    Implement precise IFT logic for the shift and shiftx cells. This is expensive.\n");
		log("\n");
		log("  -imprecise-shl-sshl\n");
		log("    Implement imprecise IFT logic for the shl and sshl cells..\n");
		log("\n");
		log("  -pmux-use-large-cells\n");
		log("    For pmux instrumentation performance purposes.\n");
		log("\n");
		log("  -conjunctive-and\n");
		log("  -conjunctive-or\n");
		log("  -conjunctive-add\n");
		log("  -conjunctive-sub\n");
		log("  -conjunctive-not\n");
		log("  -conjunctive-neg\n");
		log("  -conjunctive-and\n");
		log("  -conjunctive-or\n");
		log("  -conjunctive-mul\n");
		log("  -conjunctive-pmux\n");
		log("  -conjunctive-mux\n");
		log("  -conjunctive-eq-ne\n");
		log("  -conjunctive-ge\n");
		log("  -conjunctive-gt\n");
		log("  -conjunctive-le\n");
		log("  -conjunctive-lt\n");
		log("  -conjunctive-logic-and\n");
		log("  -conjunctive-logic-or\n");
		log("  -conjunctive-logic-not\n");
		log("  -conjunctive-reduce-and\n");
		log("  -conjunctive-shl-sshl\n");
		log("  -conjunctive-shr\n");
		log("  -conjunctive-sshr\n");
		log("  -conjunctive-shift-shiftx\n");
		log("    Implement each cell with a simple OR reduction.\n");
		log("\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		bool opt_verbose = false;
		bool opt_rtlift = false;
		bool opt_track_power_leakage = false;  // Phase 2: Power leakage tracking
		bool opt_hd_taint_prev = false;        // Gate HD on (taint | taint_prev), not taint alone
		bool opt_power_leakage_auto_scope = false;  // Auto-detect modules for aggregation
		string opt_power_leakage_scope_csv;  // Comma-separated module names
		string opt_counter_include_csv;       // Comma-separated wire-name substrings
		std::vector<string> opt_power_leakage_scope_modules;  // Parsed module names
		bool opt_conjunctive_gates = false;
		pool<string> opt_conjunctive_cells_pool;
		bool opt_precise_shiftx = false;
		bool opt_imprecise_shl_sshl = false;
		bool opt_imprecise_shr_sshr = false;
		bool opt_pmux_use_large_cells = false;
		string opt_excluded_signals_csv;
		std::vector<string> opt_excluded_signals;

		int unsigned num_taints = 1;
		log_header(design, "Executing CellIFT pass.\n");
		std::vector<std::string>::size_type argidx;

		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-num-distinct-labels") {
				num_taints = std::stoi(args[++argidx]);
				continue;
			}
			if (args[argidx] == "-verbose") {
				opt_verbose = true;
				continue;
			}
			if (args[argidx] == "-track-power-leakage") {
				opt_track_power_leakage = true;
				continue;
			}
			if (args[argidx] == "-power-leakage-scope") {
				opt_power_leakage_scope_csv = args[++argidx];
				continue;
			}
			if (args[argidx] == "-power-leakage-auto-scope") {
				opt_power_leakage_auto_scope = true;
				continue;
			}
			if (args[argidx] == "-hd-taint-prev") {
				opt_hd_taint_prev = true;
				continue;
			}
			if (args[argidx] == "-power-leakage-include-signals") {
				opt_counter_include_csv = args[++argidx];
				continue;
			}
			if (args[argidx] == "-rtlift") {
				opt_rtlift = true;
				continue;
			}
			if (args[argidx] == "-conjunctive-gates") {
				opt_conjunctive_gates = true;
				continue;
			}
			if (args[argidx] == "-exclude-signals") {
				opt_excluded_signals_csv = args[++argidx];
				continue;
			}
			if (args[argidx] == "-precise-shiftx") {
				opt_precise_shiftx = true;
				continue;
			}
			if (args[argidx] == "-imprecise-shl-sshl") {
				opt_imprecise_shl_sshl = true;
				continue;
			}
			if (args[argidx] == "-imprecise-shr-sshr") {
				opt_imprecise_shr_sshr = true;
				continue;
			}
			if (args[argidx] == "-pmux-use-large-cells") {
				opt_pmux_use_large_cells = true;
				continue;
			}
			if (args[argidx] == "-conjunctive-and") {
				opt_conjunctive_cells_pool.insert("and");
				continue;
			}
			if (args[argidx] == "-conjunctive-or") {
				opt_conjunctive_cells_pool.insert("or");
				continue;
			}
			if (args[argidx] == "-conjunctive-add") {
				opt_conjunctive_cells_pool.insert("add");
				continue;
			}
			if (args[argidx] == "-conjunctive-sub") {
				opt_conjunctive_cells_pool.insert("sub");
				continue;
			}
			if (args[argidx] == "-conjunctive-not") {
				opt_conjunctive_cells_pool.insert("not");
				continue;
			}
			if (args[argidx] == "-conjunctive-neg") {
				opt_conjunctive_cells_pool.insert("neg");
				continue;
			}
			if (args[argidx] == "-conjunctive-and") {
				opt_conjunctive_cells_pool.insert("and");
				continue;
			}
			if (args[argidx] == "-conjunctive-or") {
				opt_conjunctive_cells_pool.insert("or");
				continue;
			}
			if (args[argidx] == "-conjunctive-mul") {
				opt_conjunctive_cells_pool.insert("mul");
				continue;
			}
			if (args[argidx] == "-conjunctive-pmux") {
				opt_conjunctive_cells_pool.insert("pmux");
				continue;
			}
			if (args[argidx] == "-conjunctive-mux") {
				opt_conjunctive_cells_pool.insert("mux");
				continue;
			}
			if (args[argidx] == "-conjunctive-eq-ne") {
				opt_conjunctive_cells_pool.insert("eq-ne");
				continue;
			}
			if (args[argidx] == "-conjunctive-ge") {
				opt_conjunctive_cells_pool.insert("ge");
				continue;
			}
			if (args[argidx] == "-conjunctive-gt") {
				opt_conjunctive_cells_pool.insert("gt");
				continue;
			}
			if (args[argidx] == "-conjunctive-le") {
				opt_conjunctive_cells_pool.insert("le");
				continue;
			}
			if (args[argidx] == "-conjunctive-lt") {
				opt_conjunctive_cells_pool.insert("lt");
				continue;
			}
			if (args[argidx] == "-conjunctive-logic-and") {
				opt_conjunctive_cells_pool.insert("logic-and");
				continue;
			}
			if (args[argidx] == "-conjunctive-logic-or") {
				opt_conjunctive_cells_pool.insert("logic-or");
				continue;
			}
			if (args[argidx] == "-conjunctive-logic-not") {
				opt_conjunctive_cells_pool.insert("logic-not");
				continue;
			}
			if (args[argidx] == "-conjunctive-reduce-and") {
				opt_conjunctive_cells_pool.insert("reduce-and");
				continue;
			}
			if (args[argidx] == "-conjunctive-shl-sshl") {
				opt_conjunctive_cells_pool.insert("shl-sshl");
				continue;
			}
			if (args[argidx] == "-conjunctive-shr") {
				opt_conjunctive_cells_pool.insert("shr");
				continue;
			}
			if (args[argidx] == "-conjunctive-sshr") {
				opt_conjunctive_cells_pool.insert("sshr");
				continue;
			}
			if (args[argidx] == "-conjunctive-shift-shiftx") {
				opt_conjunctive_cells_pool.insert("shift-shiftx");
				continue;
			}
			break;
		}
		extra_args(args, argidx, design);

		// Check whether some module is selected.
		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("CellIFT cannot operate on an empty.\n");

		// Modules must be taken in inverted topological order to instrument the deepest modules first.
		// Taken from passes/techmap/flatten.cc
		TopoSort<RTLIL::Module *, IdString::compare_ptr_by_name<RTLIL::Module>> topo_modules;
		auto worklist = design->selected_modules();
		pool<RTLIL::IdString> non_top_modules;
		while (!worklist.empty()) {
			RTLIL::Module *module = *(worklist.begin());
			worklist.erase(worklist.begin());
			topo_modules.node(module);

			for (auto cell : module->selected_cells()) {
				RTLIL::Module *tpl = design->module(cell->type);
				if (tpl != nullptr) {
					if (topo_modules.database.count(tpl) == 0)
						worklist.push_back(tpl);
					topo_modules.edge(tpl, module);
					non_top_modules.insert(cell->type);
				}
			}
		}
		if (!topo_modules.sort())
			log_cmd_error("Recursive modules are not supported by CellIFT.\n");

		// Parse the excluded signals.
		if (opt_excluded_signals_csv.size()) {
			char delimiter = ',';
			int csv_start = 0;
			int end = opt_excluded_signals_csv.find(delimiter);
			while (end != -1) {
				opt_excluded_signals.push_back(opt_excluded_signals_csv.substr(csv_start, end - csv_start));
				csv_start = end + 1;
				end = opt_excluded_signals_csv.find(delimiter, csv_start);
			}
			opt_excluded_signals.push_back(opt_excluded_signals_csv.substr(csv_start, end - csv_start));
		} else if (opt_verbose)
			log("No -exclude-signals has been provided. \n");

		// Parse the power leakage scope modules.
		std::vector<std::string> counter_include;
		if (opt_counter_include_csv.size()) {
			size_t start = 0;
			while (start <= opt_counter_include_csv.size()) {
				size_t end = opt_counter_include_csv.find(',', start);
				std::string tok = opt_counter_include_csv.substr(
					start, end == std::string::npos ? std::string::npos : end - start);
				if (!tok.empty())
					counter_include.push_back(tok);
				if (end == std::string::npos)
					break;
				start = end + 1;
			}
			if (opt_verbose)
				log("Counter allowlist: %d pattern(s); only matching wires feed HW/HD\n",
				    (int)counter_include.size());
		}

		if (opt_power_leakage_scope_csv.size()) {
			char delimiter = ',';
			int csv_start = 0;
			int end = opt_power_leakage_scope_csv.find(delimiter);
			while (end != -1) {
				string module_name = opt_power_leakage_scope_csv.substr(csv_start, end - csv_start);
				// Add backslash prefix if not present (Yosys internal format)
				if (!module_name.empty() && module_name[0] != '\\')
					module_name = "\\" + module_name;
				opt_power_leakage_scope_modules.push_back(module_name);
				csv_start = end + 1;
				end = opt_power_leakage_scope_csv.find(delimiter, csv_start);
			}
			string module_name = opt_power_leakage_scope_csv.substr(csv_start, end - csv_start);
			if (!module_name.empty() && module_name[0] != '\\')
				module_name = "\\" + module_name;
			opt_power_leakage_scope_modules.push_back(module_name);
			
			if (opt_verbose) {
				log("Power leakage scope modules: ");
				for (auto &m : opt_power_leakage_scope_modules)
					log("%s ", m.c_str());
				log("\n");
			}
		}

		// Run the worker on each module.
		for (auto i = 0; i < GetSize(topo_modules.sorted); ++i) {
			RTLIL::Module *module = topo_modules.sorted[i];
			CellIFTWorker(module, opt_verbose, opt_rtlift, opt_track_power_leakage, opt_conjunctive_gates, opt_conjunctive_cells_pool, opt_precise_shiftx,
				      opt_imprecise_shl_sshl, opt_imprecise_shr_sshr, opt_pmux_use_large_cells,
				      num_taints, &opt_excluded_signals);
		}

		// Step 4: Add top-level leakage aggregation if enabled
		if (opt_track_power_leakage && topo_modules.sorted.size() > 0) {
			// The top module, as Yosys itself resolved it.
			//
			// This USED to be `topo_modules.sorted.back()` plus a check that
			// nothing instantiates it. Both parts are unsound: a topological
			// sort of the instantiation graph has one root per unreferenced
			// module, not one overall, so "last" is whichever of them the sort
			// happened to emit last -- and a dead paramod left behind by
			// specialisation is unreferenced, so it passes the "nothing
			// instantiates it" check too.
			//
			// That is not hypothetical. On Rocket the heuristic chose a stray
			// `$paramod$...\plusarg_reader`, so Step 4 instrumented a leaf
			// with 32 bits and no clock -- which means NO HD counter was
			// created at all (it needs the data_prev flop) and the HW counter
			// came out tied to 32'd0, while `rocket_mem_top` got nothing. The
			// flow always knew better: instrument.ys.tcl runs
			// `hierarchy -top $TOP_MODULE -check`, so the attribute is set.
			// Ibex and Proteus were unaffected only because the heuristic
			// happened to agree with the real top on those two designs.
			//
			// Getting this right matters most for -power-leakage-auto-scope
			// and any explicit scope, because `aggregate_counters_bottom_up`
			// is ROOTED here: a wrong root leaves every per-module counter
			// stranded, unable to reach a top-level port the testbench can
			// read.
			RTLIL::Module *top_module = design->top_module();
			bool is_top = true;
			if (!top_module) {
				// No `top` attribute (the pass was run without `hierarchy
				// -top`). Fall back to the old heuristic, and keep its guard,
				// since in that case we really have no better evidence.
				top_module = topo_modules.sorted[topo_modules.sorted.size() - 1];
				for (auto mod : design->modules()) {
					for (auto cell : mod->cells()) {
						if (design->module(cell->type) == top_module) {
							is_top = false;
							break;
						}
					}
					if (!is_top) break;
				}
				if (!is_top)
					log_warning("No module carries the `top` attribute and the "
					            "topological fallback (%s) is instantiated by "
					            "another module, so NO leakage counters were "
					            "added. Run `hierarchy -top <module>` first.\n",
					            top_module->name.c_str());
				else
					log_warning("No module carries the `top` attribute; falling "
					            "back to the topological heuristic and using %s "
					            "as the top. Run `hierarchy -top <module>` to "
					            "make this deterministic.\n",
					            top_module->name.c_str());
			} else if (opt_verbose) {
				log("  Top module (from the `top` attribute): %s\n",
				    top_module->name.c_str());
			}
			
			if (is_top && opt_verbose) {
				log("Step 4: Adding leakage aggregation counters\n");
			}
			
			if (is_top) {
				// Determine which modules should have HW/HD counters
				std::vector<RTLIL::Module*> target_modules;
				
				if (opt_power_leakage_auto_scope) {
					// Auto-detect all modules with tainted signals
					if (opt_verbose)
						log("  Using auto-scope: detecting tainted modules\n");
					target_modules = detect_tainted_modules(design, opt_verbose);
				} else if (!opt_power_leakage_scope_modules.empty()) {
					// Use explicitly specified scope modules
					if (opt_verbose)
						log("  Using explicit scope modules\n");
					for (auto &module_name : opt_power_leakage_scope_modules) {
						std::vector<RTLIL::Module*> matches = find_modules_by_name(design, module_name, opt_verbose);
						if (!matches.empty()) {
							for (auto match : matches) {
								target_modules.push_back(match);
							}
						} else {
							log_warning("Scope module not found: %s\n", module_name.c_str());
						}
					}
				} else {
					// Default: aggregate in top module only (backward compatible)
					if (opt_verbose)
						log("  Using default scope: top module only\n");
					target_modules.push_back(top_module);
				}

				// Add HW/HD counters to target modules
				bool any_non_top = false;
				for (auto target_mod : target_modules) {
					bool is_top_level = (target_mod == top_module);
					add_hw_hd_counters_to_module(target_mod, num_taints, opt_verbose, is_top_level, opt_hd_taint_prev, counter_include);
					if (!is_top_level)
						any_non_top = true;
				}

				// One bottom-up pass AFTER every target module has its own
				// counter, rather than promoting each module as it is created:
				// a parent can instantiate several instrumented children, and
				// the sum has to see all of them at once.
				if (any_non_top)
					aggregate_counters_bottom_up(design, top_module, num_taints, opt_verbose);

				// Add legacy leakage_counter for backward compatibility (OR reduction of all leakage wires)
				// This is done only at top level
				for (unsigned int taint_id = 0; taint_id < num_taints; ++taint_id) {
					std::string counter_name = "leakage_counter_t" + std::to_string(taint_id);
					RTLIL::IdString counter_id = RTLIL::escape_id(counter_name);
					
					// Create counter wire if it doesn't exist
					RTLIL::Wire *counter_wire = top_module->wire(counter_id);
					if (!counter_wire) {
						counter_wire = top_module->addWire(counter_id, 32);
						counter_wire->port_output = true;
						if (opt_verbose)
							log("  Created leakage_counter_t%d output (32-bit)\n", taint_id);
					}

					// Identify a clock for the counter
					RTLIL::Wire *clk_wire = nullptr;
					for (auto &wire_it : top_module->wires_) {
						RTLIL::Wire *w = wire_it.second;
						if (!w->port_input)
							continue;
						std::string n = w->name.str();
						if (n.find("_t0") != std::string::npos || n.find("_leak") != std::string::npos)
							continue;
						if (n == "\\clk_i" || n.find("clk_i") != std::string::npos) {
							clk_wire = w;
							break;
						}
						if (!clk_wire && (n.find("clk") != std::string::npos || n.find("clock") != std::string::npos))
							clk_wire = w;
					}

					// Aggregate all leakage wires for this taint label.
					RTLIL::SigSpec all_leaks;
					std::string leak_suffix = "_leak" + std::to_string(taint_id);
					for (auto &wire_it : top_module->wires_) {
						RTLIL::Wire *w = wire_it.second;
						if (w->name.str().find(leak_suffix) != std::string::npos)
							all_leaks.append(RTLIL::SigSpec(w));
					}

					if (all_leaks.size() == 0) {
						if (opt_verbose)
							log("  Warning: No leakage wires found for taint %d in top module.\n", taint_id);
						continue;
					}

					// Reduce OR across all leakage wires.
					RTLIL::SigSpec leak_active = top_module->ReduceOr(NEW_ID, all_leaks);
					RTLIL::Wire *leak_active_wire = top_module->addWire(NEW_ID, 1);
					top_module->connect(leak_active_wire, leak_active);

					// If we have a clock, create a registered counter; otherwise, expose a combinational value.
					if (clk_wire) {
						RTLIL::Wire *counter_reg = top_module->addWire(NEW_ID, 32);
						RTLIL::SigSpec leak_ext = RTLIL::SigSpec(leak_active_wire);
						if (leak_ext.size() < 32)
							leak_ext.append(RTLIL::SigSpec(RTLIL::State::S0, 32 - leak_ext.size()));
						// Per-cycle leakage counter: expose instantaneous activity (0/1 per cycle),
						// not a running cumulative sum.
						RTLIL::SigSpec next_val = leak_ext;
						top_module->addDff(NEW_ID, RTLIL::SigSpec(clk_wire), next_val, RTLIL::SigSpec(counter_reg));
						top_module->connect(counter_wire, counter_reg);
					} else {
						// Fall back to a 0/1 combinational indicator if no clock was found.
						RTLIL::SigSpec leak_ext = RTLIL::SigSpec(leak_active_wire);
						if (leak_ext.size() < 32)
							leak_ext.append(RTLIL::SigSpec(RTLIL::State::S0, 32 - leak_ext.size()));
						top_module->connect(counter_wire, leak_ext);
					}
				}
				
				top_module->fixup_ports();
			}
		}
	}
} CelliftPass;

PRIVATE_NAMESPACE_END
