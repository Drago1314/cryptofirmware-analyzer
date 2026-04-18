import os
from generate_test_binary import build_elf

def test_build_elf_magic():
      """
          Test that the binary generator creates a valid ELF header 
              and output length is reasonable.
                  """
      elf_data = build_elf()

    # Assert it creates more than 1KB of data
      assert len(elf_data) > 1000, "Output binary size is abnormally small"

    # Assert valid ELF magic header is present at the start
      assert elf_data.startswith(b'\x7fELF'), "Missing or invalid ELF magic header"

if __name__ == "__main__":
      test_build_elf_magic()
      print("All tests passed!")
