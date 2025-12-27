import ida_lines
from graphviewer import Node, Insn, Proc


class Proc_x86_64(Proc):
	def __init__(self):
		super().__init__()

	def is_prolog(self, node: Node):
		pat = [
			["push rbp"],
			["mov rbp, rsp"]
		]
		return self.matches_pattern(node, pat, False)
	
	def is_epilog(self, node: Node):
		pat = [
			["pop rbp"],
			["retn", "ret"]
		]
		return self.matches_pattern(node, pat, True)
		
	def is_cf(self, insn: Insn) -> bool:
		mns = [
			"jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", 
			"jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", 
			"jpe", "jnp", "jpo", "jc", "jnc", "jecxz", "jrcxz",
			"ret", "retn", "retf", "iret", "iretd", "iretq", "loop",
			"loope", "loopne", "loopz", "loopnz"
		]
		return insn.mn.strip().lower() in mns

	def matches_pattern(self, node: Node, pattern: list[list[str]], rev: bool) -> bool:
		if len(node.insns) < len(pattern):
			return False
		matches = 0
		eas = sorted(node.insns.keys())
		if rev:
			eas = list(reversed(eas))
			pattern = list(reversed(pattern))
		for i in range(len(pattern)):
			asm = " ".join(ida_lines.tag_remove(node.insns[eas[i]].asmTagged).split()).lower()
			for pat in pattern[i]:
				matches += " ".join(pat.split()).lower() == asm
		return matches == len(pattern)
