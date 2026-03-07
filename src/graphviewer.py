import os
import ida_graph
import idc
import ida_lines
import ida_ua
import json
import ida_nalt
from typing import Iterable
from enum import IntEnum
from abc import ABC, abstractmethod


class COLOR(IntEnum):
	FUNC_START = 0xD0FDF0
	FUNC_END = 0xFDD0F0
	LAST_INSN = 0xD0F0FD


class Proc(ABC):
	@abstractmethod
	def is_prolog(self, node: 'Node') -> bool:
		pass

	@abstractmethod
	def is_epilog(self, node: 'Node') -> bool:
		pass

	@abstractmethod
	def is_cf(self, insn: 'Insn') -> bool:
		pass


class Insn:
	def __init__(self, ea: int, proc: Proc):
		self.ea = ea
		self.proc = proc
		self.asmTagged = self._get_asm()
		assert self.asmTagged, f"Insn assembly decoding failed @ {self.ea:08X}"
		self.asm = ida_lines.tag_remove(self.asmTagged)
		self.mn = self._get_mn()
		self.size = self._get_size()
		assert self.size, "Insn size decoding failed @ {self.ea:08X}"
		self.line = self._get_line()
		self.isControlFlow = self._is_control_flow()
		self.nextInsnEas: set[int] = set()
		self.nextInsnExecFlow: list[int] = list()
		self.cmts: list[str] = list()
		self.parent: Node | None = None

	@classmethod
	def from_dict(cls, proc: Proc, info: dict) -> 'Insn':
		insn = cls.__new__(cls)
		insn.proc = proc
		insn.ea = info["ea"]
		insn.asmTagged = info["asmTagged"]
		insn.asm = info["asm"]
		insn.mn = info["mn"]
		insn.size = info["size"]
		insn.line = info["line"]
		insn.isControlFlow = info["isControlFlow"]
		insn.nextInsnEas = set(info["nextInsnEas"])
		insn.nextInsnExecFlow = info["nextInsnExecFlow"]
		insn.cmts = info["cmts"]
		insn.parent = None
		return insn

	def _get_asm(self):
		return ida_lines.generate_disasm_line(self.ea, ida_lines.GENDSM_FORCE_CODE)

	def _get_mn(self):
		return self.asm.replace(",", "").split()[0].lower()

	def _get_size(self):
		insn = ida_ua.insn_t()  # type: ignore
		return ida_ua.decode_insn(insn, self.ea)

	def _get_line(self):
		return (
				ida_lines.COLSTR(f"{self.ea:08X}", ida_lines.SCOLOR_KEYWORD)
				+ "    "
				+ self.asmTagged
		)

	def add_insn_exec_flow(self, ea: int):
		if not self.nextInsnExecFlow or self.nextInsnExecFlow[-1] != ea:
			self.nextInsnExecFlow.append(ea)

	def _is_control_flow(self) -> bool:
		return self.proc.is_cf(self)

	def get_cmts(self) -> str:
		if len(self.cmts) == 0:
			return str()
		color = ida_lines.SCOLOR_AUTOCMT
		if len(self.cmts) == 1:
			return ida_lines.COLSTR(f" ; {self.cmts[0]}", color)
		else:
			result = list()
			pad = str()
			dis_len = len(ida_lines.tag_remove(self.line))
			for i, cmt in enumerate(self.cmts):
				txt = f" ; {cmt}"
				if i:
					pad = " " * dis_len
				result.append(f"{pad}{ida_lines.COLSTR(txt, color)}")
			return "\n".join(result)

	def serialize(self) -> dict:
		info = {
			"ea": self.ea,
			"asmTagged": self.asmTagged,
			"asm": self.asm,
			"mn": self.mn,
			"size": self.size,
			"line": self.line,
			"isControlFlow": self.isControlFlow,
			"nextInsnEas": list(self.nextInsnEas),
			"nextInsnExecFlow": self.nextInsnExecFlow,
			"cmts": [],  # comments are later added by Graph class
		}
		return info


class Node:
	def __init__(self, start_ea: int):
		self.ea = start_ea
		self.id = int()
		self.body = self._get_label(self.ea)
		self.color = idc.DEFCOLOR
		self.insns: dict[int, Insn] = dict()
		self.toEdges: list[Node] = list()

	def __str__(self):
		s = f" [NODE #{self.id} @ {self.ea:X}] ".center(32, "=") + "\n"
		s += ida_lines.tag_remove(self.body)
		s += f"[EDGES] " + ",".join(f"{node.ea:X}" for node in self.toEdges)
		return s

	def _get_label(self, ea: int) -> str:
		ea_name = idc.get_name(ea, idc.GN_DEMANGLED)
		if ea_name:
			return ida_lines.COLSTR(f"{ea_name}\n", ida_lines.SCOLOR_KEYWORD)
		return str()

	def add_insn_dis(self, insn: Insn):
		self.body += insn.line + insn.get_cmts() + "\n"

	def add_insn(self, insn: Insn):
		if insn.ea in self.insns:
			return
		insn.parent = self
		self.insns[insn.ea] = insn

	def finalize_body(self):
		for ea, insn in sorted(self.insns.items()):
			self.add_insn_dis(insn)

	def get_insn(self, ea: int) -> Insn | None:
		return self.insns.get(ea, None)

	def remove_insn(self, ea: int):
		del self.insns[ea]

	def has_insn(self, ea: int) -> bool:
		return self.get_insn(ea) is not None

	def set_color(self, color: COLOR):
		self.color = color

	def get_all_insns(self) -> Iterable[Insn]:
		return [insn for insn in self.insns.values()]

	def get_last_insn(self) -> Insn:
		return self.insns[sorted(self.insns.keys())[-1]]


class Graph(ida_graph.GraphViewer):
	def __init__(self, name: str, proc: Proc, close_open=False):
		super().__init__(name, close_open)
		self.proc = proc
		self.nodes: dict[int, Node] = dict()
		self.execOrder: list[int] = list()
		self.insns: dict[int, Insn] = dict()
		self.lastInsn: Insn | None = None
		self.insnCmts: dict[int, list[str]] = dict()
		self._finalized = False

	def __str__(self):
		s = " GraphViewer".center(32, "=") + "\n"
		s += self.info_to_str(self.get_info()) + "\n"
		s += "\n\n".join([str(node) for node in self.nodes.values()])
		return s

	def _add_node(self, node: Node):
		node.id = self.AddNode(node)
		self.nodes[node.ea] = node

	def add_edge(self, frm: Node, to: Node):
		self.AddEdge(frm.id, to.id)
		if to == frm:
			return
		if not to in frm.toEdges:
			frm.toEdges.append(to)

	def get_node_by_start_ea(self, ea: int) -> Node | None:
		return self.nodes.get(ea, None)

	def get_node_with_ea(self, ea: int) -> Node | None:
		if insn := self.insns.get(ea, None):
			node = insn.parent
			assert node is not None, "Insn.parent is None"
			return node
		return None

	def _assign_insns(self):
		if not (node := self.get_node_by_start_ea(self.execOrder[0])):
			assert False, "first node does not exist"
		for ea in self.execOrder:
			if new_node := self.get_node_by_start_ea(ea):
				node = new_node
			node.add_insn(self.insns[ea])

	def _create_edges(self):
		for insn in self.insns.values():
			for ea in insn.nextInsnEas:
				if dst := self.get_node_by_start_ea(ea):
					src = self.get_node_with_ea(insn.ea)
					self.add_edge(src, dst)

	def _get_create_node(self, ea: int) -> Node:
		node = self.get_node_by_start_ea(ea)
		if node is None:
			node = Node(ea)
			self._add_node(node)
		return node

	def _get_duplicates_from_next_ea(self) -> list[int]:
		result = dict()
		for insn in self.insns.values():
			for ea in insn.nextInsnEas:
				result[ea] = result.get(ea, 0) + 1
		return [ea for ea, count in result.items() if count > 1]

	def _create_nodes(self):
		self._get_create_node(self.execOrder[0])
		for insn in self.insns.values():
			if insn.isControlFlow and insn.nextInsnEas:
				for ea in insn.nextInsnEas:
					self._get_create_node(ea)
		for ea in self._get_duplicates_from_next_ea():
			self._get_create_node(ea)

	def _sanity_check(self):
		self._find_duplicates()
		self._check_empty_nodes()

	def _check_empty_nodes(self):
		for node in self.nodes.values():
			assert len(node.insns), f"[empty node]: {node.ea:08x}"

	def _find_duplicates(self):
		ar = dict()
		for node in self.nodes.values():
			for ea in node.insns.keys():
				ar[ea] = ar.get(ea, 0) + 1
		for ea, n in ar.items():
			assert n == 1, f"[duplicated instruction]: {ea:08x}"

	def _finalize_nodes(self):
		for node in self.nodes.values():
			node.finalize_body()

	def get_insn(self, ea: int) -> Insn | None:
		if node := self.get_node_with_ea(ea):
			return node.get_insn(ea)
		return None

	def clear_insn_cmt(self, ea: int):
		if self.insnCmts.get(ea, None):
			del self.insnCmts[ea]

	def add_insn_cmt(self, ea: int, cmt: str):
		lst = self.insnCmts.setdefault(ea, list())
		if "\n" in cmt:
			for cmt in cmt.split("\n"):
				lst.append(cmt)
		else:
			lst.append(cmt)

	def get_insn_cmts(self, ea: int) -> str:
		return "\n".join(self.insnCmts.get(ea, list()))

	def _assign_cmts(self):
		for ea, cmts in self.insnCmts.items():
			if insn := self.get_insn(ea):
				insn.cmts = cmts

	def _assign_node_colors(self):
		for node in self.nodes.values():
			if self.proc.is_prolog(node):
				node.set_color(COLOR.FUNC_START)
			elif self.proc.is_epilog(node):
				node.set_color(COLOR.FUNC_END)
		if last_node := self.get_node_with_ea(self.execOrder[-1]):
			last_node.set_color(COLOR.LAST_INSN)

	def get_all_nodes(self) -> list[Node]:
		return [node for node in self.nodes.values()]

	def process(self, ea: int):
		self.execOrder.append(ea)
		insn = self.insns.setdefault(ea, Insn(ea, self.proc))
		if self.lastInsn:
			self.lastInsn.nextInsnEas.add(ea)
			self.lastInsn.add_insn_exec_flow(ea)
		self.lastInsn = insn

	def finalize(self):
		if self._finalized:
			return
		self._create_nodes()
		self._assign_insns()
		self._assign_cmts()
		self._finalize_nodes()
		self._create_edges()
		self._assign_node_colors()
		self._sanity_check()
		self._finalized = True

	# ------------------------ MISC ------------------------

	def get_info(self) -> dict:
		info = {
			"database": idc.get_root_filename(),
			"crc": ida_nalt.retrieve_input_file_crc32(),
			"imagebase": ida_nalt.get_imagebase(),
			"nodeCount": len(self.nodes),
			"insnCount": len(self.insns),
			"startEa": self.execOrder[0],
		}
		return info

	@staticmethod
	def info_to_str(info: dict) -> str:
		s = f"[+] database: {info['database']}" + "\n"
		s += f"[+] crc: {info['crc']:X}" + "\n"
		s += f"[+] imagebase: {info['imagebase']:X}" + "\n"
		s += f"[+] nodes: {info['nodeCount']}" + "\n"
		s += f"[+] instructions: {info['insnCount']}" + "\n"
		s += f"[+] start: {info['startEa']:X} ({info['startEa'] - info['imagebase']:X})" + "\n"
		return s

	def dot(self) -> str:
		"""
		Return in graphviz .dot format
		"""
		if not self._finalized:
			self.finalize()
		dot = list()
		dot.append('digraph "GraphViewer" {')
		dot.append('graph [bgcolor="#E4F7FE", rankdir=TB, pad=1, margin=0];')
		dot.append(
			'node [fontname="monospace", fontsize=13, shape=box, style=filled, penwidth=1.0, margin="0.15,0.1", fillcolor="#FFFFFF", fontcolor="#00087B"];')
		dot.append('edge [fontname="Arial", fontsize=8, color="#333333", penwidth=1.5, arrowhead=vee];')
		for node in self.nodes.values():
			processed = []
			for line in ida_lines.tag_remove(node.body).splitlines():
				processed.append(f'{line}<br align="left"/>')
			dot.append(f'"loc_{node.ea:X}" [label=<{"".join(processed)}>];')
			for target in node.toEdges:
				dot.append(f'"loc_{node.ea:X}" -> "loc_{target.ea:X}";')
		dot.append('}')
		return "\n".join(dot)

	# ------------------------ SAVING & LOADING ------------------------

	def save(self, path: str):
		if not self._finalized:
			self.finalize()
		info = dict()
		info["info"] = self.get_info()
		info["execOrder"] = self.execOrder
		info["insns"] = [insn.serialize() for insn in self.insns.values()]
		info["lastInsn"] = self.lastInsn.ea
		info["insnCmts"] = self.insnCmts
		data = json.dumps(info, separators=(",", ":"))
		with open(path, "w") as fh:
			fh.write(data)
		print(" GraphViewer Save ".center(32, "="))
		print(self.info_to_str(info["info"]))

	def load(self, path: str):
		assert os.access(path, os.R_OK), f'Invalid path: "{path}"'
		with open(path, "r") as fh:
			data = fh.read()
		info = json.loads(data)
		self.execOrder = info["execOrder"]
		self.insns = {insn["ea"]: Insn.from_dict(self.proc, insn) for insn in info["insns"]}
		self.lastInsn = self.insns[info["lastInsn"]]
		assert self.lastInsn
		self.insnCmts = {int(ea): cmt for ea, cmt in info["insnCmts"].items()}
		self.finalize()
		print(" GraphViewer Load ".center(32, "="))
		print(self.info_to_str(info["info"]))

	# ------------------------ INHERITED ------------------------

	def OnRefresh(self):
		if not self._finalized:
			self.finalize()
		return True

	def OnGetText(self, node_id):
		return self.GetNodeText(node_id)

	def GetNodeText(self, node_id):
		node = self._nodes[node_id]
		return (node.body, node.color)

	def Show(self):
		super().Show()
