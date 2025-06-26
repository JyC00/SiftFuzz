# SiftFuzz

SiftFuzz is a structure-driven triage module designed to enhance coverage-guided fuzzers by incorporating structural analysis and differential fusion. It prioritizes and merges inputs based on their structural uniqueness, enabling fine-grained deduplication and structure-aware recombination.

## Highlights

- Locality-sensitive structural feature matching for fast similarity detection.
- MinHash signature computation and chunk-wise feature bucketing.
- Differential fusion based on format detection and differential binary sequences.
- Penalized Hamming similarity and trace-level similarity comparison.
- Designed as a pluggable, lightweight component with minimal dependencies.

## Directory Structure

| Path        | Description                                            |
| ----------- | ------------------------------------------------------ |
| `Fusion/`   | Core logic: structural triage, similarity detection, fusion |
| `Fuzzer/`   | Docker-based build system for 5 major fuzzers with auto-injection |
| `README.md` | Project overview, and build guide   

> 🔧 Note: You will need to integrate this module manually with your fuzzer (e.g., AFL++) by invoking the provided triage and fusion functions in your `afl-fuzz.c` logic, particularly around the seed evaluation and corpus admission stages.
> The integration part is **not included** for now, but will be added in future updates.

## Usage

To build a Docker image containing AFL, AFL++, MOpt-AFL, SeamFuzz, and SLIME — all injected with the `Fusion` logic:

```bash
cd Fuzzer
docker build -t siftfuzz .
docker run -it siftfuzz


