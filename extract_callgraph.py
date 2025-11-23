#!/usr/bin/env python3
"""
extract_callgraph.py

Build a function-level call graph using angr and keep only a limited number of
nodes (default 15) to keep the visualization readable.

Usage:
  python3 extract_callgraph.py /path/to/binary -o out_prefix \
      [--max-nodes 15] [--start START] [--render]

Notes:
 - START can be a function name substring (case-insensitive) or an address
   literal like 0x401000 or 4198400. Defaults to the function containing the
   module entry point.
 - Rendering uses Graphviz (tries sfdp first, then dot).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections import deque
from typing import Iterable

import angr
import networkx as nx


def parse_start(start: str, cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> int | None:
    start = start.strip()
    if not start:
        return None
    try:
        if start.lower().startswith("0x"):
            return int(start, 16)
        return int(start)
    except ValueError:
        target = start.lower()
        for func in cfg.kb.functions.values():
            if func.name and target in func.name.lower():
                return func.addr
    return None


def find_entry_function(cfg: angr.analyses.cfg.cfg_fast.CFGFast, entry_addr: int) -> int | None:
    func = cfg.kb.functions.get(entry_addr)
    if func is not None:
        return func.addr
    for f in cfg.kb.functions.values():
        try:
            if f.contains_addr(entry_addr):
                return f.addr
        except Exception:
            continue
    return None


def bfs_limit(graph: nx.DiGraph, start: int, limit: int) -> set[int]:
    if start not in graph:
        return set()
    selected: set[int] = set()
    queue: deque[int] = deque([start])

    def enqueue(nodes: Iterable[int]) -> None:
        for node in nodes:
            if node in selected or node in queue:
                continue
            if len(selected) + len(queue) >= limit:
                return
            queue.append(node)

    while queue and len(selected) < limit:
        node = queue.popleft()
        if node in selected:
            continue
        selected.add(node)

        enqueue(graph.successors(node))
        enqueue(graph.predecessors(node))

    return selected


def write_dot(graph: nx.DiGraph, cfg, path: str) -> None:
    with open(path, "w") as f:
        # Modern graph styling with solid backgrounds, rounded corners, custom fonts
        f.write("digraph callgraph {\n")
        f.write("  // Graph-level styling\n")
        f.write('  graph [bgcolor="#0a0e27", pad="0.5", nodesep="1.0", ranksep="1.2", splines=ortho];\n')
        f.write('  node [shape=box, style="filled,rounded", fontname="Fira Code,Consolas,monospace", fontsize=11, fontcolor="#e0e0e0", penwidth=2];\n')
        f.write('  edge [color="#4a9eff88", penwidth=2.0, arrowsize=0.8];\n')
        f.write("\n")
        
        # Node styling with gradient-like colors
        for node in graph.nodes():
            func = cfg.kb.functions.get(node)
            if func is None:
                label = hex(node)
                node_style = 'fillcolor="#1a1f3a", color="#3d5a80"'
            else:
                name = func.name or "sub_" + hex(func.addr)[2:]
                label = f"{name}\\n{hex(func.addr)}"
                
                # Color-code based on function type/name patterns
                if "main" in name.lower() or "entry" in name.lower():
                    # Entry point - vibrant cyan
                    node_style = 'fillcolor="#0d7377:#14919b", gradientangle=90, color="#2ec4b6", fontcolor="#ffffff", fontsize=12'
                elif any(suspicious in name.lower() for suspicious in ["inject", "allocate", "remote", "virtual", "create", "write"]):
                    # Suspicious APIs - red gradient
                    node_style = 'fillcolor="#c1121f:#780000", gradientangle=90, color="#ff006e", fontcolor="#ffffff", fontsize=11'
                elif name.startswith("sub_"):
                    # Unknown functions - dark blue
                    node_style = 'fillcolor="#1e2749", color="#4361ee"'
                else:
                    # Standard functions - teal gradient
                    node_style = 'fillcolor="#1a535c:#264653", gradientangle=90, color="#4ecdc4"'
            
            label = label.replace('"', "'")
            f.write(f'  "{hex(node)}" [label="{label}", {node_style}];\n')
        
        f.write("\n  // Edges\n")
        for src, dst in graph.edges():
            f.write(f'  "{hex(src)}" -> "{hex(dst)}";\n')
        f.write("}\n")


def render_png(dot_path: str, png_path: str) -> None:
    for engine in ("sfdp", "dot"):
        try:
            subprocess.check_call([engine, "-Tpng", dot_path, "-o", png_path])
            return
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError("Graphviz rendering failed (engines tried: sfdp, dot)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract a limited-size call graph with angr")
    parser.add_argument("binary", help="Path to PE/ELF binary")
    parser.add_argument("-o", "--out", default="callgraph", help="Output prefix")
    parser.add_argument("--max-nodes", type=int, default=15, help="Maximum number of callgraph nodes to keep")
    parser.add_argument("--start", default="", help="Start function (name substring or address)")
    parser.add_argument("--accurate", action="store_true", help="Use CFGAccurate (slower)")
    parser.add_argument("--render", action="store_true", help="Render PNG with graphviz")
    parser.add_argument("--no-load-libs", action="store_true", help="Disable auto-loading shared libraries")
    args = parser.parse_args()

    bin_path = os.path.abspath(args.binary)
    if not os.path.exists(bin_path):
        print("[!] Binary not found:", bin_path)
        sys.exit(1)

    proj_kwargs = {}
    if args.no_load_libs:
        proj_kwargs["auto_load_libs"] = False

    print("[*] Loading project:", bin_path)
    proj = angr.Project(bin_path, **proj_kwargs)

    print("[*] Building CFG ({} mode)...".format("accurate" if args.accurate else "fast"))
    cfg = proj.analyses.CFGAccurate() if args.accurate else proj.analyses.CFGFast()

    chosen_addr: int | None
    if args.start:
        chosen_addr = parse_start(args.start, cfg)
        if chosen_addr is None:
            print("[!] Could not resolve start function from:", args.start)
            sys.exit(1)
    else:
        chosen_addr = find_entry_function(cfg, proj.entry)
        if chosen_addr is None:
            print("[!] Could not find function containing entry point; specify --start explicitly.")
            sys.exit(1)

    callgraph = cfg.kb.callgraph
    if chosen_addr not in callgraph:
        print(f"[!] Start function {hex(chosen_addr)} not present in call graph. Try --accurate or another start address.")
        sys.exit(1)

    print(f"[*] Starting at {hex(chosen_addr)}, limiting to {args.max_nodes} nodes")
    selected = bfs_limit(callgraph, chosen_addr, max(args.max_nodes, 1))

    if not selected:
        print("[!] No nodes selected. Exiting.")
        sys.exit(1)

    subgraph = callgraph.subgraph(selected).copy()
    print(f"[*] Subgraph nodes={subgraph.number_of_nodes()} edges={subgraph.number_of_edges()}")

    dot_path = args.out + ".callgraph.dot"
    write_dot(subgraph, cfg, dot_path)
    print("[*] DOT written to", dot_path)

    if args.render:
        png_path = args.out + ".callgraph.png"
        try:
            render_png(dot_path, png_path)
            print("[*] PNG written to", png_path)
        except Exception as exc:
            print("[!] Rendering failed:", exc)


if __name__ == "__main__":
    main()
