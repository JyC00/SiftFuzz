#ifndef AFL_UTIL_H
#define AFL_UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "types.h"


extern u32 fusion_round;
struct afl_state;
typedef struct afl_state afl_state_t;

struct queue_entry;

#define MINHASH_DIM 1023
#define MINHASH_BUCKETS 100000
#define BUCKET_CHUNKS 16
#define CHUNK_LEN (MINHASH_DIM / BUCKET_CHUNKS)
#define JACCARD_THRESHOLD 0.85
#define MAX_LINES 1024
#define MAX_LINE_LEN 512

typedef enum {
    DIFF_EQUAL,
    DIFF_INSERT,
    DIFF_DELETE
  } DiffType;
  
  typedef struct {
    DiffType type;
    int index_a;
    int index_b;
    uint8_t byte;
  } DiffOp;
  
  typedef struct {
    uint8_t* data;
    uint32_t len;
  } BinData;
  
struct queue_entry;


static inline uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);
void compute_minhash_signature(u8* data, u32 len, u32 signature_out[MINHASH_DIM]);
float hamming_similarity_weighted(BinData a, BinData b);
struct queue_entry* find_similar_path_entry(afl_state_t *afl);
struct queue_entry* binary_structure_duplicated_filter(afl_state_t* afl, u8* data, u32 len);
int detect_format(struct queue_entry* q);

DiffOp* myers_diff_binary(const u8* a, u32 len_a, const u8* b, u32 len_b, int* out_op_count);
u8* fuse_seed_by_diff_mem(const u8* mem_b, u32 len_b, struct queue_entry* a, u32* out_len);
void add_to_feature_pool(struct queue_entry* q);

void try_fuse_with_similar_seed(char** argv, u8* buf, u32 len, u8 fault);
void write_fusion_stats(void);


#endif // AFL_UTIL_H
