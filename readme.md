# GraphViewer

A programmatic framework for visualizing instruction execution traces as interactive Control Flow Graphs (CFG) within IDA Pro.

![preview](preview.png)

## Overview

Analyzing heavily obfuscated "spaghetti code" can be an overwhelming task. When static analysis fails to define functions or resolve complex control flow, traditional linear disassembly becomes difficult to follow.

This tool solves that problem by converting execution traces recorded from debuggers or emulators into interactive graphs. By visualizing the **actual execution path**, it automatically detects basic block boundaries and leverages IDA's native UI to help you identify patterns, loops, and logic structures that are otherwise hard to follow in linear disassembly.

## Key Features

- Automatically reconstructs a graph from a linear list of executed addresses.
- Detects basic block boundaries at branch targets and where execution paths converge.
- Automatically identifies and colors function prologues and epilogues.
- Distinctly colors the final executed block for easy orientation.
- Supports multi-line comments per instruction, allowing you to embed trace metadata (like register values) directly into the graph.
- Built on an extensible `Proc` base class, making it easy to support custom architectures.
- Save and load complete graphs to and from disk for later analysis.
- Allows exporting to Graphviz `.dot` format for visualization and further analysis.

## Basic Block Boundaries
GraphViewer defines a new basic block boundary at any instruction that satisfies either of the following conditions:

- **It is a control flow instruction.** Any instruction that is the destination of a control flow instruction (jump, call, etc.) starts a new block. This is determined by `Proc.is_cf()`, which your architecture implementation defines.
- **It is a convergence point.** If the same address appears as the next instruction from two or more different instructions across all processed passes, it means multiple execution paths lead to it. GraphViewer detects this and promotes the address to a block start.

This means the graph reflects only what was actually observed in the trace. An address that was branched to in one pass but fell through in another will still be recognized as a block boundary, because it was seen as a branch target at least once.


## Usage
```python
proc = Proc_x86_64()
trace_graph = Graph("Graph Name", proc)

trace = [
    0x140001000, # push rbp
    0x140001001, # mov rbp, rsp
    0x140001004, # sub rsp, 20h
    0x140001008, # call rax
    0x14000100D, # add rsp, 20h
    0x140001011, # pop rbp
    0x140001012  # retn
]

for ea in trace:
    trace_graph.process(ea)

trace_graph.add_insn_cmt(0x140001008, "Indirect call target")
trace_graph.add_insn_cmt(0x140001008, "Observed RAX: 0x7FF01234")

trace_graph.save(file_path)
trace_graph.Show()
```

#### Loading Trace From File
```python
proc = Proc_x86_64()
trace_graph = Graph("My Trace", proc).load(file_path)
trace_graph.Show()
```

#### Processing Multiple Execution Passes
When re-running the same code from the start (e.g. a second emulation pass), call `.restart()` before feeding the first instruction of the new pass. Without it, GraphViewer would incorrectly create an edge from the last instruction to the starting instruction. Because functions can call themselves recursively, GraphViewer cannot automatically determine when a new pass begins — it is up to the user to decide when it does.

```python
proc = Proc_x86_64()
trace_graph = Graph("Multi-pass Trace", proc)

for pass_index, pass_trace in enumerate(all_passes):
    if pass_index > 0:
        trace_graph.restart()
    for ea in pass_trace:
        trace_graph.process(ea)

trace_graph.Show()
```

#### Handling Undecodable Branches During Code Coverage
When building code coverage of an obfuscated function by emulating multiple execution paths, some branches may lead to addresses that are intentionally invalid or never meant to be executed (opaque predicates). These branches often point into the middle of an existing valid instruction — breaking it into an undecodable byte sequence — rather than to a clean instruction boundary. Feeding such an address to `.process()` will raise `InsnDecodeException`.

The recommended pattern is to catch the exception and call `.restart()` immediately, then continue with the next pass. This discards the broken path cleanly without corrupting the graph state or creating a spurious edge into the next pass.

```python
proc = Proc_x86_64()
trace_graph = Graph("Coverage Trace", proc)

for pass_index, pass_trace in enumerate(all_passes):
    if pass_index > 0:
        trace_graph.restart()
    for ea in pass_trace:
        try:
            trace_graph.process(ea)
        except InsnDecodeException:
            trace_graph.restart()
            break

trace_graph.Show()
```

#### Highlighting Instructions
Individual instructions can be visually highlighted in the graph using `.set_insn_highlight()` on the `Graph` object. This is useful for drawing attention to instructions of interest — such as tainted data sources, suspicious memory accesses, or any instruction identified during analysis.

By default, `.set_insn_highlight()` uses `SCOLOR_IMPNAME` (typically pink), but any IDA's `SCOLOR_` color constant can be passed.

```python
tainted_eas = [0x140001008, 0x14000100D]
for ea in tainted_eas:
    trace_graph.set_insn_highlight(ea)

trace_graph.Show()
```

## Important Notes
- This tool visualizes the *recorded path*. It does not discover branches that were not taken during the trace.
- For the clearest results, it is recommended to filter out instructions past `call` (except when the call is in fact obfuscated `jmp`) and keep processing again after return.