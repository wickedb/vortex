#include <vx_spawn2.h>
#include "common.h"

__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t lt  = threadIdx.x;
	auto lm = reinterpret_cast<volatile uint32_t*>(__local_mem());
	volatile uint32_t stk[STACK_WORDS];
	if (arg->mode == 0) {
		lm[lt] = PAT(lt);
		for (uint32_t k = 0; k < STACK_WORDS; ++k)
			stk[k] = PAT(k);
	} else {
		uint32_t lh = (lm[lt] == PAT(lt)) ? 1u : 0u;
		uint32_t sh = 0;
		for (uint32_t k = 0; k < STACK_WORDS; ++k)
			sh += (stk[k] == PAT(k)) ? 1u : 0u;
		if (idx < arg->num_points) {
			reinterpret_cast<uint32_t*>(arg->lmem_hits_addr)[idx]  = lh;
			reinterpret_cast<uint32_t*>(arg->stack_hits_addr)[idx] = sh;
		}
	}
}
