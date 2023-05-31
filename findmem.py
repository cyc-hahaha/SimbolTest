import angr
import sys
project=angr.Project('00_angr_find')
start_addr=0x08048626
init_state=project.factory.blank_state(addr=start_addr)


your_string = "IICLTGRK"
size = len(your_string)

# 使用memory.store()将字符串存储到内存地址中
init_state.memory.store(0x08048763, init_state.solver.BVV(your_string.encode(), size * 8))

find_addr=0x0804868C
simulation = project.factory.simgr(init_state)
simulation.explore(find=find_addr)
found=simulation.found[0]

loaded_data = found.memory.load(0x08048763, size)
data_bytes = found.solver.eval(loaded_data, cast_to=bytes)
print(data_bytes.decode())