---
layout: post
title: "PR Read: Packed-sequence-metadata-caching in Unsloth"
date: 2026-06-12 15:02:00+0800
description: How caching packed sequence metadata with Python object identity eliminates 160 GPU stalls per forward pass and speeds up training by 14.3%.
tags: performance cuda llm-training
categories: en
---

> Originally published in Chinese on [Zhihu](https://zhuanlan.zhihu.com/p/2049007976841847901).

> This post was written by a **human**. Claude Code was used to understand the code and algorithms.

[https://github.com/unslothai/unsloth/pull/4243](https://github.com/unslothai/unsloth/pull/4243)

### What is packing

When training LLMs, a batch contains many sentences of varying lengths. To fit them into a single matrix for computation, the traditional approach is padding (pad shorter sentences with 0s to match the longest one), which wastes compute.
Packing (also called padding-free) concatenates multiple sentences into one long sequence, and additionally passes a `seq_lengths` (the length of each sentence) to tell the model where the boundaries of each sentence are.

### The problem: the GPU stalls waiting for the CPU at every layer

A model has N layers (for example, Qwen3 14B has 40 layers). During each layer's forward pass, three functions are called to process seq_lengths:
- get_packed_info_from_kwargs: lengths.max().item()
- build_sdpa_packed_attention_mask: seq_lengths.sum().item() + .tolist()
- build_xformers_block_causal_mask: seq_lengths.to("cpu")

These .item() / .tolist() / .to("cpu") are all D2H (Device→Host) operations, moving data from GPU to CPU. GPU computation is asynchronous (it queues up tasks and returns immediately), but reading a value requires the queue to drain, triggering `cudaStreamSynchronize`: the CPU must wait for the GPU to finish its tasks.

40 layers × 4 syncs = 160 GPU stalls.
Although each individual wait is extremely short, the values obtained across all 160 calls are identical, because seq_lengths does not change within a single forward pass. And more importantly:

### The N intermediate waits are more than N times as expensive as a single final wait

**Waiting once at the end**: The final synchronization at most waits for the last batch of GPU tasks still in flight to drain. Once done, there is nothing after it, or even if there is a next batch of tasks, it won't arrive for a long time. So this wait does not delay anything downstream. Its cost is solely the "queue drain wait."

**Waiting once in the middle**: In addition to the same queue drain wait, there is also:
1. **While the CPU is waiting, it cannot continue feeding the next batch of tasks to the GPU.** Normally the CPU runs ahead of the GPU, responsible for preparing the next batch of data. But now it is waiting, so when the GPU next needs data that the CPU was supposed to prepare, the CPU may not have it ready yet, causing additional stalls.
2. **GPU computation and kernel launch overhead cannot be hidden**: Launching GPU kernels has overhead. When the queue is full, the GPU can initiate the launch of the next kernel while the current one is nearly finished, thereby hiding the overhead. When the queue is empty, this overhead can no longer be hidden.

So each intermediate synchronization = kernel launch overhead + (potential) CPU data preparation overhead + GPU task queue drain, whereas the final wait only has GPU task queue drain. This is why it is more than N times as expensive.

### The fix: cache using Python object identity

Within each forward pass, all layers receive the same seq_lengths tensor object. So:
```python
if cache.seq_lengths is seq_lengths:   # same object → reuse
    return cache.result
```

If it is the first time and seq_lengths does not yet exist in the cache, perform one D2H transfer, compute the result, and store it in the cache.

When the next batch arrives, seq_lengths is a new tensor, the `is` check fails, and the cache is naturally invalidated — no manual invalidation needed.

### Results

Before: rows of tiny green dots are cudaStreamSynchronize calls, densely packed across forward and backward passes.

After: the green dots are almost entirely gone — there is only one at the very beginning (first layer computes + caches), and all subsequent layers hit the cache. The Forward block's width shrinks from ~500ms to 301ms, and Backward from ~1020ms to 960ms.

Gains (Qwen3 14B QLoRA SFT):
- Forward 43.3% faster (most impacted — synchronization operations accounted for a large share)
- Backward 5.8% faster
- Overall batch 14.3% faster
