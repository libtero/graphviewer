import ida_graph
import idc
import ida_lines
from enum import IntEnum
from abc import ABC, abstractmethod


class COLOR(IntEnum):
	FUNC_START = 0xD0FDF0
	FUNC_END = 0xFDD0F0
	LAST_INSN = 0xD0F0FD


class Proc(ABC):
	def __init__(self):
		pass

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
		assert self.asmTagged, "Insn assembly decoding failed @ {self.ea:08X}"
		self.asm = ida_lines.tag_remove(self.asmTagged)
		self.mn = self._get_mn()
		self.line = self._get_line()
		self.isControlFlow = self._is_control_flow()
		self.nextInsnEas: set[int] = set()
		self.cmts: list[str] = list()

	def _get_asm(self):
		return ida_lines.generate_disasm_line(self.ea, ida_lines.GENDSM_FORCE_CODE)
	
	def _get_mn(self):
		return self.asm.replace(",", "").split()[0].lower()

	def _get_line(self):
		return (
			ida_lines.COLSTR(f"{self.ea:08X}", ida_lines.SCOLOR_KEYWORD)
			+ "    "
			+ self.asmTagged
		)

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


class Node:
	def __init__(self, start_ea: int):
		self.ea = start_ea
		self.id = int()
		self.body = self._get_label(start_ea)
		self.color = idc.DEFCOLOR
		self.insns: dict[int, Insn] = dict()

	def _get_label(self, ea: int) -> str:
		ea_name = idc.get_name(ea, idc.GN_DEMANGLED)
		if ea_name:
			return ida_lines.COLSTR(f"{ea_name}\n", ida_lines.SCOLOR_KEYWORD)
		return str()

	def add_insn_dis(self, insn: Insn):
		self.body += insn.line + insn.get_cmts() + "\n"

	def add_insn(self, inst: Insn):
		if inst.ea in self.insns:
			return
		self.insns[inst.ea] = inst

	def finalize_body(self):
		for ea, insn in sorted(self.insns.items()):
			self.add_insn_dis(insn)

	def get_insn(self, ea: int) -> Insn | None:
		return self.insns.get(ea, None)

	def remove_insn(self, ea: int):
		del self.insns[ea]

	def has_insn(self, ea: int) -> bool:
		return self.get_insn(ea) != None

	def set_color(self, color: COLOR):
		self.color = color


class Graph(ida_graph.GraphViewer):
	def __init__(self, proc: Proc):
		super().__init__("Trace Graph", True)
		self.proc = proc
		self.nodes: dict[int, Node] = dict()
		self.execOrder: list[int] = list()
		self.insns: dict[int, Insn] = dict()
		self.lastInsn: Insn | None = None
		self.insnCmts: dict[int, list[str]] = dict()

	def OnRefresh(self):
		self._finalize()
		return True

	def OnGetText(self, node_id):
		return self.GetNodeText(node_id)

	def GetNodeText(self, node_id):
		node = self._nodes[node_id]
		return (node.body, node.color)

	def Show(self):
		super().Show()

	# ------------------------ CUSTOM DEFS ------------------------

	def _add_node(self, node):
		node.id = self.AddNode(node)
		self.nodes[node.ea] = node

	def add_edge(self, frm, to):
		self.AddEdge(frm.id, to.id)

	def get_node_by_start_ea(self, ea: int) -> Node | None:
		return self.nodes.get(ea, None)

	def get_node_with_ea(self, ea: int) -> Node | None:
		for node in self.nodes.values():
			if ea in node.insns.keys():
				return node

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

	def _count_duplicates_from_next_ea(self) -> list[int]:
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
		for ea in self._count_duplicates_from_next_ea():
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

	def process(self, ea: int):
		self.execOrder.append(ea)
		insn = self.insns.setdefault(ea, Insn(ea, self.proc))
		if self.lastInsn:
			self.lastInsn.nextInsnEas.add(ea)
		self.lastInsn = insn

	def _finalize(self):
		self._create_nodes()
		self._assign_insns()
		self._assign_cmts()
		self._finalize_nodes()
		self._create_edges()
		self._assign_node_colors()
		self._sanity_check()
