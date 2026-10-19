"""Reject altered disassembly and an unrelated build in recovery inspection."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/workflows/scripts'))
import reinspect_release421 as recovery

def fixture():
    # Three NOPs and BL 0x3000 from 0x100c; the label is independent ELF evidence.
    words = [0xd503201f] * 3 + [0x94000000 | ((0x3000 - 0x100c) // 4)]
    code = b''.join(struct.pack('<I', word) for word in words)
    image = bytes(0x1000) + code
    fn = {'address': '0x1000', 'image_offset': '0x1000', 'size': len(code),
          'hex': code.hex(), 'sha256': hashlib.sha256(code).hexdigest()}
    lines = [f'{0x1000 + i * 4:016x}:\t{word:08x}\tnop' for i, word in enumerate(words)]
    lines[-1] = f'{0x100c:016x}:\t{words[-1]:08x}\tbl\t{0x3000:016x} <_copy_to_user>'
    return image, [fn], {'text_base': '0x0'}, '\n'.join(lines)

class RecoveryTests(unittest.TestCase):
    def test_exact_bound_elf_instruction_restores_symbol(self):
        image, functions, meta, text = fixture()
        self.assertEqual(recovery.restore_copy_symbols(image, functions, meta, text)['copy_to_user_addresses'], ['0x3000'])

    def test_changed_disassembly_word_is_rejected(self):
        image, functions, meta, text = fixture()
        with self.assertRaisesRegex(RuntimeError, 'bytes differ'):
            recovery.restore_copy_symbols(image, functions, meta, text.replace('d503201f', 'd503201e', 1))

    def test_target_label_cannot_override_bl_bytes(self):
        image, functions, meta, text = fixture()
        with self.assertRaisesRegex(RuntimeError, 'BL address differs'):
            recovery.restore_copy_symbols(image, functions, meta, text.replace('0000000000003000', '0000000000003004'))

    def test_label_must_name_exact_function_entry(self):
        image, functions, meta, text = fixture()
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            recovery.restore_copy_symbols(image, functions, meta, text.replace('<_copy_to_user>', '<_copy_to_user+0x4>'))

    def test_duplicate_instruction_pc_is_rejected(self):
        image, functions, meta, text = fixture()
        with self.assertRaises(RuntimeError):
            recovery.restore_copy_symbols(image, functions, meta, text + '\n' + text.splitlines()[0])

    def test_another_source_head_is_rejected_before_downloading(self):
        run = {'id': recovery.SOURCE_RUN, 'repository': {'full_name': recovery.REPO}, 'head_sha': '0' * 40}
        with tempfile.TemporaryDirectory() as tmp, patch.object(recovery, 'api', return_value=run):
            with self.assertRaisesRegex(RuntimeError, 'repository/head'):
                recovery.capture_source(Path(tmp) / 'provenance')

if __name__ == '__main__':
    unittest.main()
