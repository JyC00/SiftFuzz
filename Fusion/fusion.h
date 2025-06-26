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

#define MINHASH_DIM     1023
#define MINHASH_BUCKETS 100000

#define SUBPOOL_CNT 3
extern const uint32_t CHUNKS_PER_POOL[SUBPOOL_CNT];
extern const uint32_t LEN_THRESHOLD[SUBPOOL_CNT-1];

typedef struct bucket_node {
  struct queue_entry   *q;
  struct bucket_node   *next_in_bucket;
} bucket_node_t;

typedef struct {
  bucket_node_t       *buckets[MINHASH_BUCKETS];
  uint32_t             chunk_cnt;
  uint32_t             chunk_len;
} feature_subpool_t;

typedef enum { DIFF_EQUAL, DIFF_INSERT, DIFF_DELETE } DiffType;

typedef struct {
  DiffType   type;
  int        index_a;
  int        index_b;
  uint8_t    byte;
} DiffOp;

typedef struct {
  uint8_t   *data;
  uint32_t   len;
} BinData;

static inline uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);

void   compute_minhash_signature(u8* data, u32 len, uint32_t sig_out[MINHASH_DIM]);
float  hamming_similarity_weighted(BinData a, BinData b);

struct queue_entry* find_similar_path_entry(afl_state_t *afl);
struct queue_entry* binary_structure_duplicated_filter(afl_state_t* afl, u8* data, u32 len);
void   add_to_feature_pool(struct queue_entry* q);
void   destroy_feature_pool(void);

int    detect_format(struct queue_entry* q);

DiffOp* myers_diff_binary(const u8* a, u32 len_a, const u8* b, u32 len_b, int* out_cnt);
u8*    fuse_seed_by_diff_mem(const u8* mem_b, u32 len_b, struct queue_entry* a, u32* out_len);

void   try_fuse_with_similar_seed(char** argv, u8* buf, u32 len, u8 fault);
void   write_fusion_stats(void);

#endif /* AFL_UTIL_H */
