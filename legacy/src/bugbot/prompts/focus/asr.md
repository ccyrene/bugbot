This repository is an **ML / speech-recognition model codebase**. Treat training scripts, evaluation harnesses, and data pipelines as production. The priority order below is **ML-flavoured** — don't try to fit a generic web-service threat model on top of it.

1. **Data leakage between splits** — the highest-impact silent bug class. Watch for:
   - Speaker / session overlap across train / val / test splits (especially for ASR / speaker-conditioned models — same speaker in multiple splits breaks generalisation claims).
   - Normalisation stats (`mean`, `std`, `MVN`, `cmvn`, per-feature scaler) fit on the whole dataset before the split, instead of fit on train only and applied to val/test.
   - Augmentation / `SpecAugment` / noise mixing applied to eval or test sets.
   - Tokenizer / BPE / SentencePiece / vocab fit on full corpus including eval transcripts.
   - Pretraining checkpoint or LM trained on text that overlaps the test transcripts.
   - Time-series / sliding-window splits that leak future frames into the train view.

2. **Reproducibility** — every run should be reconstructable:
   - Random seeds not set across `random` / `numpy` / `torch` / `torch.cuda` / the dataloader's `generator` + `worker_init_fn`.
   - `torch.backends.cudnn.deterministic` / `benchmark` flags not set when reproducibility is claimed.
   - Non-deterministic ops left in eval code (`scatter_add_` on CUDA, certain attention kernels) without justification.
   - Checkpoint paths / dataset paths / config paths hardcoded to a developer's `/home/...`, breaking other runs.
   - Pinned versions missing from `requirements.txt` / `environment.yml` / `pyproject.toml` for `torch`, `torchaudio`, `transformers`, `cuda`, drivers — silent ABI drift bites later.
   - Config not logged alongside the checkpoint (no way to know which hyperparams produced a given run).

3. **Training correctness** — the loss going down isn't enough:
   - Loss function mismatched to the reported metric (e.g. CTC loss + WER metric where blank handling differs; reporting val accuracy on a balanced subset of an imbalanced eval set).
   - Gradient flow broken — `.detach()` / `with torch.no_grad():` accidentally wrapping the trainable path, `requires_grad=False` on parameters that should learn, `optimizer.zero_grad()` missing or in the wrong place.
   - Mixed precision (`autocast` / `GradScaler`) loss-scale logic wrong — unscaled `clip_grad_norm_`, gradient explosion masked by NaN skips, scaler step before unscale.
   - LR schedule applied at the wrong granularity (per-batch vs per-epoch), warmup steps off by an order of magnitude, schedule not restored from checkpoint on resume.
   - Model not switched between `train()` / `eval()` modes around validation — BatchNorm / Dropout misbehave.
   - Distributed: not averaging loss/metrics across ranks, gradient accumulation that doesn't divide loss by accumulation steps, `DDP` wrapping an `EMA` or `swa_model` shadow copy.

4. **Audio / feature pipeline bugs** — domain-specific landmines:
   - Sample-rate mismatch between dataset (e.g. 8 kHz telephony) and feature extractor configured for 16 kHz — silent resample or wrong stft window.
   - Channel order / mono-vs-stereo assumption mismatches; collapsing stereo by averaging when the model expects channel 0 only.
   - Normalisation order wrong (e.g. log-mel before mean-variance norm vs. after), windowing or `n_fft` / `hop_length` inconsistent between training and inference.
   - Padding direction wrong, padding token included in CTC loss, **attention/key-padding mask not set** so the model attends to padding, length tensor off-by-one against feature time-axis.
   - Tokenizer / vocab mismatch between training and inference (different BPE model, different special-token IDs, `<unk>` / `<blank>` / `<pad>` ID drift between checkpoints).
   - Streaming / chunked inference using non-causal layers or attention that peeks across chunk boundaries.

5. **Optimisation** — wasted compute is a real bug:
   - DataLoader bottleneck (`num_workers=0`, no `pin_memory`, no `persistent_workers`, sync I/O inside `__getitem__`) leaving the GPU idle.
   - Wrong gradient-accumulation interaction with `DDP` (no `no_sync()` context), needlessly synchronous all-reduce on every micro-batch.
   - Unbatched feature extraction in a Python loop where a vectorised / GPU op would do.
   - Memory: `.cpu()` / `.numpy()` round-trips inside the training step, full feature tensors retained for logging, gradient checkpointing missed on a model that won't fit otherwise.
   - Mixed precision not enabled on a CUDA target where it would clearly fit and help — flag the missed opportunity rather than ignore.

Notes:
- Security data leaks (keys, tokens, PII in checkpoints/configs) **are still a finding** — the local scanner runs first and will catch obvious patterns, but if you also spot one, raise it as `secret-leak`.
- Style / formatting / naming is still out of scope — `black`/`ruff` does that.
