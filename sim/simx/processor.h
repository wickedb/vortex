// Copyright © 2019-2023
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <stdint.h>
#include <functional>

namespace vortex {

class RAM;
class Memory;
class ProcessorImpl;

class Processor {
public:
  Processor();
  ~Processor();

  void attach_ram(RAM* mem);

  void reset();

  int run();

  // Advance the simulator by one cycle. On the first call after a
  // reset() (or on the very first call), the KMU is started so warps
  // dispatch into the cluster. Returns true while work remains
  // (clusters running or channels carrying packets); false once the
  // program has finished and the channels have drained.
  //
  // Used by external simulators that drive Vortex's clock from their
  // own event loop (SST in sim/simx/sst/, gem5 in sim/simx/gem5/).
  bool cycle();

  void start_kmu();

  bool any_running() const;

  class Core* get_first_core() const;

  // Install a hook that mirrors every accepted memory request to an
  // external simulator (e.g. SST memHierarchy) for timing observability.
  // Host-side plumbing like attach_ram: the local data path stays in
  // Vortex's RAM.
  void set_mem_telemetry_hook(std::function<void(const struct MemReq&)> hook);

  // `issuer` is the command-processor queue (tenant) that sent the write.
  int dcr_write(uint32_t addr, uint32_t value, uint32_t issuer = 0);

  int dcr_read(uint32_t addr, uint32_t tag, uint32_t* value);

  // The checker on the command processor's device path (D7): judges one
  // device line a CP command moves for queue `issuer`. Proceeds when no
  // checker is built. See MemChecker::cp_authorize.
  bool cp_authorize(uint64_t addr, bool is_write, uint32_t issuer,
                    uint32_t* taint, bool to_host);

private:
  ProcessorImpl* impl_;
};

}
