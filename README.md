# SiftFuzz

SiftFuzz is a structure-driven triage module designed to enhance coverage-guided fuzzers by incorporating structural analysis and differential fusion. It prioritizes and merges inputs based on their structural uniqueness, enabling fine-grained deduplication and structure-aware recombination.

## Highlights

- Locality-sensitive structural feature matching for fast similarity detection.
- MinHash signature computation and chunk-wise feature bucketing.
- Differential fusion based on Myers diff and file format detection.
- Penalized Hamming similarity and trace-level similarity comparison.
- Designed as a pluggable, lightweight component with minimal dependencies.

## Repository Structure

| File           | Description                                    |
| -------------- | ---------------------------------------------- |
| `fusion.h/.c`  | Core fusion and structural filtering logic     |
| `README.md`    | This file                                      |

> 🔧 Note: You will need to integrate this module manually with your fuzzer (e.g., AFL++) by invoking the provided triage and fusion functions in your `afl-fuzz.c` logic, particularly around the seed evaluation and corpus admission stages.
> The integration part is **not included** for now, but will be added in future updates.

<!-- ## 📌 Integration Guidance (Not included here)

To fully utilize SiftFuzz, you are expected to:
1. Include `fusion.h` in your fuzzer’s codebase (e.g., in `afl-fuzz.c`).
2. Initialize and manage the `FeaturePool`, `minhash_signature`, and `seen_flag` in your queue structure.
1. At the triage stage, invoke:

   ```c
   struct queue_entry* match = binary_structure_duplicated_filter(afl, input_buf, input_len);
   ```

2. If `match` is not `NULL`, apply structure-aware fusion:

   ```c
   u8* fused_data = fuse_seed_by_diff_mem(input_buf, input_len, match, &new_len);
   ```

3. Save or insert the fused data accordingly. -->

<!-- ## 📊 Evaluation Setup

We integrated SiftFuzz into **five representative fuzzers** (e.g., AFL, AFL++, MOpt-AFL, SEAMFuzz, SLIME) and evaluated on **eight real-world targets** from UniBench. Key evaluation metrics include:

- **Edge coverage** and **crash count**
- **Structural classification precision**
- **Seed fusion quality**
- **Overhead of structural analysis** -->

<!-- ## 📦 Build and Use (Standalone)

This repository is not meant to be built as a standalone binary. Instead, it is designed as a **library-style component** to be included into a CGF fuzzer build. You can compile the `.c` files with your target fuzzer and link them into its core.

```bash
gcc -c fusion.c minhash.c similarity.c diff.c format.c save.c
```

## 🔬 Key Algorithms

- **MinHash Signature**: Approximates structural locality for fast bucketing.
- **Penalized Similarity**: Adjusts Hamming distance for variable-length inputs.
- **Format-Aware Fusion**: Detects file structure (e.g., PDF, PNG) to retain headers.
- **Myers Diff**: Extracts insert/delete/equal segments for structural merging. -->

<!-- ## 📎 Paper and Citation

If you use SiftFuzz in your work, please consider citing:

```bibtex
@misc{SiftFuzz2024,
  author = {Chen, Jingyi},
  title = {Triage Beyond Coverage: Harnessing Structural Diversity in Fuzzing Inputs},
  year = {2024},
  howpublished = {\url{https://github.com/JyC00/SiftFuzz}},
}
``` -->

## 🔚 Limitations and Future Work

- The integration part is not included for now, but will be added in future updates.

<!-- ## 🔓 License

This project is released under the MIT License. -->
