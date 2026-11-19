"""Merge the LoRA adapter into the fp16 base -> training/out/merged (fp16 safetensors + tokenizer)."""
import torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
H = Path(__file__).resolve().parent
base = H / "hf" / "Qwen3-4B-Instruct-2507"
m = AutoModelForCausalLM.from_pretrained(base, dtype=torch.float16, device_map={"": 0})
m = PeftModel.from_pretrained(m, H / "out" / "adapter").merge_and_unload()
m.save_pretrained(H / "out" / "merged", safe_serialization=True)
AutoTokenizer.from_pretrained(base).save_pretrained(H / "out" / "merged")
print("merged")
