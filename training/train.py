"""QLoRA fine-tune of Qwen3-4B-Instruct-2507 on training/data/train.jsonl. No message text is printed or logged.
Usage: python training/train.py [--epochs 2] [--lr 2e-4] [--limit N]
"""
import argparse, json, math, os, random, time
from pathlib import Path
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, Trainer, TrainingArguments, TrainerCallback
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

HERE = Path(__file__).resolve().parent
BASE = HERE / "hf" / "Qwen3-4B-Instruct-2507"
OUT = HERE / "out" / "adapter"
MAXLEN = 3072


def encode(tok, ex):
    prompt = tok.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=True)
    p = tok(prompt, add_special_tokens=False)["input_ids"]
    c = tok(ex["target"] + "<|im_end|>\n", add_special_tokens=False)["input_ids"]
    ids = p + c
    assert len(ids) <= MAXLEN, len(ids)          # truncate nothing
    return {"input_ids": ids, "labels": [-100] * len(p) + c}


class DS(torch.utils.data.Dataset):
    def __init__(self, rows): self.rows = rows
    def __len__(self): return len(self.rows)
    def __getitem__(self, i): return self.rows[i]


def collate(b, pad):
    m = max(len(x["input_ids"]) for x in b)
    ids = torch.full((len(b), m), pad); lab = torch.full((len(b), m), -100); att = torch.zeros((len(b), m), dtype=torch.long)
    for i, x in enumerate(b):
        n = len(x["input_ids"]); ids[i, :n] = torch.tensor(x["input_ids"]); lab[i, :n] = torch.tensor(x["labels"]); att[i, :n] = 1
    return {"input_ids": ids, "labels": lab, "attention_mask": att}


class LeanTrainer(Trainer):
    """Loss on completion tokens only, computed on just those positions (avoids the 2.4k x 152k logits tensor that spilled out of VRAM)."""
    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        inner = model.base_model.model
        h = inner.model(input_ids=inputs["input_ids"], attention_mask=inputs["attention_mask"]).last_hidden_state[:, :-1]
        lab = inputs["labels"][:, 1:]
        m = lab != -100
        logits = inner.lm_head(h[m]).float()
        loss = torch.nn.functional.cross_entropy(logits, lab[m])
        return (loss, None) if return_outputs else loss


class Log(TrainerCallback):
    def on_log(self, args, state, control, logs=None, **kw):
        if logs:
            with open(HERE / "out" / "train_log.txt", "a") as f:
                f.write(json.dumps({"step": state.global_step, "t": round(time.time()), **{k: v for k, v in logs.items() if isinstance(v, (int, float))}}) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--accum", type=int, default=16)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    random.seed(0); torch.manual_seed(0)
    tok = AutoTokenizer.from_pretrained(BASE)
    rows = [json.loads(l) for l in open(HERE / "data" / "train.jsonl", encoding="utf-8")]
    if a.limit: rows = rows[:a.limit]
    data = [encode(tok, r) for r in rows]
    L = [len(d["input_ids"]) for d in data]
    print("examples", len(data), "len min/mean/max", min(L), sum(L) // len(L), max(L), flush=True)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(BASE, quantization_config=bnb, dtype=torch.bfloat16, device_map={"": 0}, attn_implementation="sdpa")
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    cfg = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, task_type="CAUSAL_LM",
                     target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, cfg)
    model.print_trainable_parameters()
    args = TrainingArguments(output_dir=str(HERE / "out" / "ckpt"), per_device_train_batch_size=1, gradient_accumulation_steps=a.accum,
                             num_train_epochs=a.epochs, learning_rate=a.lr, lr_scheduler_type="cosine", warmup_steps=2, bf16=True,
                             logging_steps=1, save_strategy="no", report_to=[], gradient_checkpointing=True,
                             gradient_checkpointing_kwargs={"use_reentrant": False}, optim="paged_adamw_8bit", weight_decay=0.0,
                             remove_unused_columns=False, dataloader_num_workers=0, seed=0)
    tr = LeanTrainer(model=model, args=args, train_dataset=DS(data), data_collator=lambda b: collate(b, tok.pad_token_id), callbacks=[Log()])
    t0 = time.time()
    tr.train()
    model.save_pretrained(OUT)
    print("done seconds", round(time.time() - t0), "peak GB", round(torch.cuda.max_memory_allocated() / 1e9, 2))


if __name__ == "__main__":
    main()
