#include "afl-fuzz.h"
#include "fusion.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

u32 fusion_round = 20;
u32 total_fusion_to_queue = 0;

const uint32_t CHUNKS_PER_POOL[SUBPOOL_CNT] = { 8, 16, 32 };
const uint32_t LEN_THRESHOLD[SUBPOOL_CNT-1] = { 32 * 1024, 128 * 1024 };

static feature_subpool_t HFeaturePool[SUBPOOL_CNT];

static inline uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t *key_x4 = (const uint32_t *) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h = (h * 5) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t *) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void compute_minhash_signature(u8* data, u32 len, u32 sig_out[MINHASH_DIM]) {
  for (u32 i = 0; i < MINHASH_DIM; i++) {
    sig_out[i] = murmur3_32(data, len, i * 0x45d9f3b);
  }
}

static void init_feature_pools(void) {
  for (uint32_t i = 0; i < SUBPOOL_CNT; ++i) {
    HFeaturePool[i].chunk_cnt = CHUNKS_PER_POOL[i];
    HFeaturePool[i].chunk_len = MINHASH_DIM / CHUNKS_PER_POOL[i];
    for (uint32_t b = 0; b < MINHASH_BUCKETS; ++b)
      HFeaturePool[i].buckets[b] = NULL;
  }
}

__attribute__((constructor))
static void __fusion_init(void) { init_feature_pools(); }

void destroy_feature_pool(void) {
  for (uint32_t p = 0; p < SUBPOOL_CNT; ++p) {
    for (uint32_t b = 0; b < MINHASH_BUCKETS; ++b) {
      bucket_node_t *node = HFeaturePool[p].buckets[b];
      while (node) {
        bucket_node_t *nxt = node->next_in_bucket;
        ck_free(node);
        node = nxt;
      }
      HFeaturePool[p].buckets[b] = NULL;
    }
  }
}

void add_to_feature_pool(struct queue_entry *q) {
  for (uint32_t p = 0; p < SUBPOOL_CNT; ++p) {
    uint32_t M = HFeaturePool[p].chunk_cnt;
    uint32_t len = HFeaturePool[p].chunk_len;
    uint8_t seen[MINHASH_BUCKETS] = {0};
    for (uint32_t c = 0; c < M; ++c) {
      uint32_t *chunk = &q->minhash_signature[c * len];
      uint32_t bucket = murmur3_32((uint8_t*)chunk, len * 4, 0xABCD1234) % MINHASH_BUCKETS;
      if (seen[bucket]) continue;
      seen[bucket] = 1;
      bucket_node_t *node = ck_alloc(sizeof(bucket_node_t));
      node->q = q;
      node->next_in_bucket = HFeaturePool[p].buckets[bucket];
      HFeaturePool[p].buckets[bucket] = node;
    }
  }
}

static uint32_t pick_pool_priority(u32 len) {
  if (len < LEN_THRESHOLD[0]) return 0;
  if (len < LEN_THRESHOLD[1]) return 1;
  return 2;
}

struct queue_entry* binary_structure_duplicated_filter(afl_state_t* afl, u8* data, u32 len) {
  uint32_t sig[MINHASH_DIM];
  compute_minhash_signature(data, len, sig);
  uint32_t first = pick_pool_priority(len);
  for (uint32_t round = 0; round < SUBPOOL_CNT; ++round) {
    uint32_t pidx = (first + round) % SUBPOOL_CNT;
    feature_subpool_t *pool = &HFeaturePool[pidx];
    for (uint32_t c = 0; c < pool->chunk_cnt; ++c) {
      uint32_t *chunk = &sig[c * pool->chunk_len];
      uint32_t bucket = murmur3_32((uint8_t*)chunk, pool->chunk_len * 4, 0xABCD1234) % MINHASH_BUCKETS;
      bucket_node_t *node = pool->buckets[bucket];
      while (node) {
        struct queue_entry *cur = node->q;
        if (cur->seen_flag) {
          node = node->next_in_bucket;
          continue;
        }
        cur->seen_flag = 1;
        int fd = open((const char*)cur->fname, O_RDONLY);
        if (fd < 0) {
          node = node->next_in_bucket;
          continue;
        }
        struct stat st;
        if (fstat(fd, &st) < 0 || st.st_size == 0) {
          close(fd);
          node = node->next_in_bucket;
          continue;
        }
        u8* other = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (other == MAP_FAILED) {
          node = node->next_in_bucket;
          continue;
        }
        float sim = hamming_similarity_weighted((BinData){data, len}, (BinData){other, st.st_size});
        munmap(other, st.st_size);
        if (sim > 0.80f) {
          for (u32 i = 0; i < afl->queued_items; i++) afl->queue_buf[i]->seen_flag = 0;
          return NULL;
        }
        node = node->next_in_bucket;
      }
    }
  }
  for (u32 i = 0; i < afl->queued_items; i++) afl->queue_buf[i]->seen_flag = 0;
  return find_similar_path_entry(afl);
}

int detect_format(struct queue_entry* q) {
    FILE* fp = fopen(q->fname, "rb");
    if (!fp) {
        perror("[ERROR] open file");
        return 0;
    }

    uint8_t header[64] = {0};
    size_t read_len = fread(header, 1, sizeof(header), fp);
    fclose(fp);

    if (read_len >= 4 && memcmp(header, "%PDF", 4) == 0) return 64;               
    if (read_len >= 8 && memcmp(header, "\x89PNG\r\n\x1a\n", 8) == 0) return 64;  
    if (read_len >= 6 && memcmp(header, "GIF89a", 6) == 0) return 32;             
    if (read_len >= 3 && memcmp(header, "ID3", 3) == 0) return 32;               
    if (read_len >= 2 && header[0] == 0xFF && (header[1] & 0xE0) == 0xE0) return 32; 
    if (read_len >= 3 && memcmp(header, "\xFF\xD8\xFF", 3) == 0) return 64;      
    if (read_len >= 12 && memcmp(header, "RIFF", 4) == 0 && memcmp(header + 8, "WAVE", 4) == 0) return 64; 
    if (read_len >= 12 && memcmp(header, "RIFF", 4) == 0 && memcmp(header + 8, "AVI ", 4) == 0) return 64; 
    if (read_len >= 2 && memcmp(header, "PK", 2) == 0) return 32;                
    if (read_len >= 4 && (memcmp(header, "II*\x00", 4) == 0 || memcmp(header, "MM\x00*", 4) == 0)) return 32; 
    if (read_len >= 8 && memcmp(header + 4, "ftyp", 4) == 0) return 64;         
    if (read_len >= 3 && memcmp(header, "FLV", 3) == 0) return 32;                
    if (read_len >= 3 && (memcmp(header, "CWS", 3) == 0 || memcmp(header, "FWS", 3) == 0)) return 32; 
    if (read_len >= 4 && memcmp(header, "\xd4\xc3\xb2\xa1", 4) == 0) return 24;   
    if (read_len >= 2 && memcmp(header, "MZ", 2) == 0) return 64;                 
    if (read_len >= 4 && memcmp(header, "\x7f""ELF", 4) == 0) return 64;          
    if (read_len >= 4 && memcmp(header, "CDF\x01", 4) == 0) return 32;            
    if (read_len >= 2 && memcmp(header, "\x01\xDA", 2) == 0) return 32;           
    if (read_len >= 2 && memcmp(header, "BM", 2) == 0) return 32;                 
    if (read_len >= 2 && header[0] == 0 && header[1] == 0) return 0;             


    if (read_len >= 2 && header[0] == 'P' && header[1] >= '1' && header[1] <= '6') {
        switch (header[1]) {
            case '1': case '4': return 16;  
            case '2': case '5': return 16;  
            case '3': case '6': return 16; 
        }
    }

    if (read_len >= 3 && header[1] == 0 && header[2] == 2) return 32;             
    if (read_len >= 1 && (header[0] == '{' || header[0] == '[')) return 0;        
    if (read_len >= 1 && isascii(header[0])) return 0;                           

    return 0; 
}


DiffOp* myers_diff_binary(const u8* a, u32 len_a, const u8* b, u32 len_b, int* out_op_count) {
  int** dp = malloc((len_a + 1) * sizeof(int*));
  for (int i = 0; i <= len_a; i++) {
    dp[i] = malloc((len_b + 1) * sizeof(int));
  }

  for (int i = 0; i <= len_a; i++) {
    for (int j = 0; j <= len_b; j++) {
      if (i == 0) dp[i][j] = j;
      else if (j == 0) dp[i][j] = i;
      else if (a[i - 1] == b[j - 1]) dp[i][j] = dp[i - 1][j - 1];
      else {
        int del = dp[i - 1][j];
        int ins = dp[i][j - 1];
        int rep = dp[i - 1][j - 1];
        dp[i][j] = 1 + (del < ins ? (del < rep ? del : rep) : (ins < rep ? ins : rep));
      }
    }
  }

  DiffOp* ops = malloc((len_a + len_b) * sizeof(DiffOp));
  int count = 0;
  int i = len_a, j = len_b;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] == b[j - 1]) {
      ops[count++] = (DiffOp){DIFF_EQUAL, i - 1, j - 1, a[i - 1]};
      i--; j--;
    } else if (j > 0 && (i == 0 || dp[i][j - 1] <= dp[i - 1][j])) {
      ops[count++] = (DiffOp){DIFF_INSERT, -1, j - 1, b[j - 1]};
      j--;
    } else {
      ops[count++] = (DiffOp){DIFF_DELETE, i - 1, -1, a[i - 1]};
      i--;
    }
  }

  for (int k = 0; k <= len_a; k++) free(dp[k]);
  free(dp);

  for (int l = 0; l < count / 2; l++) {
    DiffOp tmp = ops[l];
    ops[l] = ops[count - 1 - l];
    ops[count - 1 - l] = tmp;
  }

  *out_op_count = count;
  return ops;
}

u8* fuse_seed_by_diff_mem(const u8* mem_b, u32 len_b, struct queue_entry* a, u32* out_len) {

  int fd = open((const char*)a->fname, O_RDONLY);
  if (fd < 0) return NULL;

  struct stat st;
  if (fstat(fd, &st) < 0 || st.st_size == 0) {
    close(fd);
    return NULL;
  }

  u32 len_a = st.st_size;
  u8* mem_a = mmap(0, len_a, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (mem_a == MAP_FAILED) return NULL;

  int header_len = detect_format(a);

  int op_count = 0;
  DiffOp* ops = myers_diff_binary(mem_a, len_a, mem_b, len_b, &op_count);
  if (!ops) {
    munmap(mem_a, len_a);
    return NULL;
  }

  u8* fused = malloc(len_a + len_b + 128);
  int pos = 0;

  if (header_len > 0 && len_a >= header_len) {
    memcpy(fused + pos, mem_a, header_len);
    pos += header_len;
  }

  for (int i = 0; i < op_count; i++) {
    DiffOp op = ops[i];
    int keep = rand() % 2;
    switch (op.type) {
      case DIFF_DELETE:
        if (rand() % 2) {
          fused[pos++] = op.byte;
        }
        break;
      case DIFF_EQUAL:
          fused[pos++] = op.byte;
          break;

      case DIFF_INSERT:
          if (rand() % 2) {
              fused[pos++] = op.byte;
          }
          break;
    }
  }

  free(ops);
  munmap(mem_a, len_a);

  *out_len = pos;
  u8* resized_fused = ck_alloc(pos);
  memcpy(resized_fused, fused, pos);
  free(fused);
  *out_len = pos;


  return resized_fused;

}




void add_to_feature_pool(struct queue_entry* q) {
  u8 seen[MINHASH_BUCKETS] = {0}; 

  for (int i = 0; i < BUCKET_CHUNKS; i++) {
      uint32_t* chunk = &q->minhash_signature[i * CHUNK_LEN];
      uint32_t bucket_id = murmur3_32((uint8_t*)chunk, CHUNK_LEN * 4, 0xABCD1234) % MINHASH_BUCKETS;

      if (seen[bucket_id]) continue; 

      seen[bucket_id] = 1;

      struct bucket_node* node = ck_alloc(sizeof(struct bucket_node));
      node->q = q;
      node->next_in_bucket = FeaturePool[bucket_id];
      FeaturePool[bucket_id] = node;
  }
}


void destroy_feature_pool() {
  for (int i = 0; i < MINHASH_BUCKETS; i++) {
    struct bucket_node* node = FeaturePool[i];
    while (node) {
      struct bucket_node* next = node->next_in_bucket;
      ck_free(node);
      node = next;
    }
    FeaturePool[i] = NULL;  
  }
}

float compute_trace_bitwise_similarity(const u8* trace1, const u8* trace2, u32 size) {
  u32 same_bits = 0;
  for (u32 i = 0; i < size; i++) {
      u8 diff = trace1[i] ^ trace2[i];
      same_bits += 8 - __builtin_popcount(diff); 
  }
  return (float)same_bits / (size * 8);
}

u8* save_fused_input(afl_state_t* afl, u8* mem, u32 len) {
  static u32 fused_file_id = 0;

  u8* fname = alloc_printf("%s/fused_%06u", afl->out_dir, fused_file_id++);
  FILE* f = fopen((char*)fname, "wb");
  if (!f || fwrite(mem, 1, len, f) != len) {
    perror("[fused] Failed to save fused input");
    if (f) fclose(f);
    ck_free(fname);
    return NULL;
  }

  fclose(f);
  return fname;  
}
  
  