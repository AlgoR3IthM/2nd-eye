# training/ - QLoRA fine-tune of Signal C (qwen3-4b-2507)

STATUS: data + scripts + toolchain are ready; the fine-tune itself was NOT run to completion. The 16 GB GPU was already ~13 GB full
(LM Studio's llama-server is the CUDA backend and keeps the live-demo model plus its KV cache resident, and the team's evaluate.py runs
kept it busy). Our QLoRA run (2.4k-token sequences, 4-bit base) started but did not finish a single optimiser step in 8 minutes because
it had no VRAM left and was spilling to shared memory. Unloading LM Studio's model is not allowed, so we stopped. No model, no GGUF, no
base-vs-fine-tuned numbers exist. Ship the base model.

## Toolchain (works)
`uv venv training\.venv --python 3.12`; torch 2.11+cu128, transformers 5.23, peft 0.21, trl 1.18, bitsandbytes 0.50 (native Windows),
datasets, accelerate. Base weights in `training/hf/Qwen3-4B-Instruct-2507`. llama.cpp b12535 CPU release (`llama-quantize.exe`) and
source (`convert_hf_to_gguf.py`) in `training/tools`. (gguf python requirements still to install: `uv pip install --python training\.venv\Scripts\python.exe -r training\tools\src\llama.cpp-b12535\requirements.txt`.)

## Data
`python training/gen_data.py --n 1300 --seed 7` -> `data/train.jsonl` (1170) and `data/dev.jsonl` (130). Labels correct by construction:
every sender message is built from pieces (phrase family per flag, evidence span marked in the template, so the evidence string occurs
verbatim). 11 scam story builders (family emergency, account takeover, romance, bank, courier, authority, tech support, marketplace,
investment, job, prize) with slots from the official catalog and invented look-alike domains, indirect payment asks (taxi, ticket, rent,
medicine, "un mic ajutor", gift cards, payment apps), ID photo asks, obfuscation (no diacritics, leet, case, no punctuation, typos, emoji),
1-10 message threads with reader replies and a late hook for ~35%, 41% genuine hard negatives (official notices, delivered codes,
urgent-but-genuine, money already paid, door/wifi codes, relatives sharing a number). The input is built by importing backend/llm.py
(`_clean_messages`, `_build_user_prompt`, `SYSTEM_PROMPT`), so it is byte-identical to the live prompt at generation time
(`data/source_hashes.txt` = md5 of llm.py and patterns.json used). The prompt changes upstream: regenerate before training.
Nothing from Cerinte/ or the selftest; LM Studio was not used. Max sequence 2.5k tokens with the current (longer) prompt.

Teammate data: `python training/convert_raul.py` converts `Nou Raul/train_data.jsonl` (289 distinct inputs, all parsed) into per-message
evidence with rules.detect(): 412 of 531 flags placed with a verbatim quote (78%), 0 examples dropped; unplaced flags are dropped, so some
examples under-label. claimed_org/person_name are null there. Output: `data/raul_train.jsonl` (261), `data/raul_dev.jsonl` (28); not merged
into train.jsonl yet (concatenate to use).

## Reproduce (when the GPU is free, ~6 GB needed, ~40-60 min)
```
training\.venv\Scripts\python.exe training\gen_data.py --n 1300
training\.venv\Scripts\python.exe training\train.py --epochs 2 --accum 16      # adapter -> out\adapter, loss in out\train_log.txt
training\.venv\Scripts\python.exe training\merge.py                             # fp16 merge -> out\merged
training\.venv\Scripts\python.exe training\eval_dev.py                          # dev metrics (pass hf\Qwen3-4B-Instruct-2507 for base)
training\.venv\Scripts\python.exe training\tools\src\llama.cpp-b12535\convert_hf_to_gguf.py training\out\merged --outtype f16 --outfile training\out\ft-f16.gguf
training\tools\bin\llama-quantize.exe training\out\ft-f16.gguf training\out\2ndeye-qwen3-4b-ft-Q4_K_M.gguf Q4_K_M
lms import --copy --user-repo 2ndeye/qwen3-4b-ft training\out\2ndeye-qwen3-4b-ft-Q4_K_M.gguf
```
## Results
None (see status). 

## What synthetic data can and cannot teach
It can teach the output format, the evidence-quote discipline, obfuscation robustness and the "quiet on genuine" habit. It cannot teach
the real distribution: templated phrases are far less varied than real scammers, the model may memorise our phrase families, and our
labels follow our own reading of the rules. The base model plus the hardened prompt (which now carries many of these cases as rules and
examples) is likely already close; a fine-tune must be judged on validation, selftest and redteam before it ships.

## Romance emphasis (team request)
Generator now makes ROMANCE ~28% of scam examples (204 of 730 in the current set): slow threads of 6-10 messages, excuses (offshore, army,
widower, doctor abroad, ship), late indirect asks (plane ticket, customs on a parcel, frozen account, gift cards, payment apps, crypto
"investment" with RF_TOO_GOOD), plus affection-only genuine negatives ("mi-e dor de tine", "te iubesc", small favours). Not trained.

## Run outcome (15:00-16:00)
Training succeeded only in a reduced form: 88 examples (random slice of train.jsonl, ~28% romance), 1 epoch, 11 optimiser steps (accum 8),
LoRA r16/a32/d0.05, 536 s, peak 9 GB. A full epoch (74 steps) projected to 2.5 h because the GPU is shared with LM Studio. train.py's
LeanTrainer computes the loss on completion positions only (logged loss is scaled x8 by accumulation: ~15 at step 1 to ~0.86 at step 11,
i.e. ~1.9 -> ~0.11 per token). Merged, converted and quantised to `training/out/2ndeye-qwen3-4b-ft-Q4_K_M.gguf` (2.5 GB), imported to
LM Studio (key `qwen3-4b-ft`, folder 2ndeye/qwen3-4b-ft). NOT loaded, NOT compared with the base; dev-set evaluation was stopped
unfinished at the team's request. No quality claim can be made. Note: an 88-example run is a smoke test, not a proper fine-tune.
