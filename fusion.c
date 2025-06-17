#include "afl-fuzz.h"
#include "fusion.h"

u32 fusion_round = 20;


u32 total_fusion_to_queue = 0;
struct bucket_node* FeaturePool[MINHASH_BUCKETS] = {NULL};


uint32_t compute_chunk_hash(uint32_t* sig_chunk) {
    return murmur3_32((uint8_t*)sig_chunk, CHUNK_LEN * 4, 0xABCD1234) % MINHASH_BUCKETS;
}
  

static inline uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  const int nblocks = len / 4;
  const uint32_t* blocks = (const uint32_t*)(key);
  for (int i = 0; i < nblocks; i++) {
    uint32_t k = blocks[i];
    k *= c1; k = (k << 15) | (k >> 17); k *= c2;
    h ^= k; h = (h << 13) | (h >> 19); h = h * 5 + 0xe6546b64;
  }

  const uint8_t* tail = (const uint8_t*)(key + nblocks * 4);
  uint32_t k1 = 0;
  switch (len & 3) {
    case 3: k1 ^= tail[2] << 16;
    case 2: k1 ^= tail[1] << 8;
    case 1: k1 ^= tail[0]; k1 *= c1; k1 = (k1 << 15) | (k1 >> 17); k1 *= c2; h ^= k1;
  }

  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}
  

void compute_minhash_signature(u8* data, u32 len, u32 signature_out[MINHASH_DIM]) {

  const u32 window_size = 16;   
  const u32 step_size = 8;     

  for (u32 i = 0; i < MINHASH_DIM; i++) {
      signature_out[i] = 0xffffffff;
  }

  if (len < window_size) return;

  for (u32 offset = 0; offset + window_size <= len; offset += step_size) {

      u8* window = data + offset;

      u32 base_hash = murmur3_32(window, window_size, 0x12345678);

      for (u32 j = 0; j < MINHASH_DIM; j++) {
          u32 h = murmur3_32((u8*)&base_hash, 4, j * 0x9e3779b9);
          if (h < signature_out[j]) {
              signature_out[j] = h;
          }
      }
  }
}

float hamming_similarity_weighted(BinData a, BinData b) {
  uint32_t min_len = (a.len < b.len) ? a.len : b.len;
  uint32_t max_len = (a.len > b.len) ? a.len : b.len;
  float penalty_factor = (float)min_len / (float)max_len;

  uint32_t dist = 0;

  for (uint32_t i = 0; i < min_len; i++) {
      uint8_t diff = a.data[i] ^ b.data[i];
      while (diff) {
          dist += diff & 1;
          diff >>= 1;
      }
  }

  uint32_t extra_bytes = max_len - min_len;
  uint32_t penalty = (uint32_t)(8.0 * extra_bytes * penalty_factor);

  uint32_t total_possible = max_len * 8; 
  uint32_t total_distance = dist + penalty;

  return 1.0f - ((float)total_distance / total_possible);
}

struct queue_entry* find_similar_path_entry(afl_state_t *afl) {

  if (!afl || !afl->queue_buf || afl->queued_items == 0) return NULL;

  u32 attempts = 0;

  while (attempts < 3) {  
    u32 idx = rand() % afl->queued_items;
    struct queue_entry *q = afl->queue_buf[idx];
    if (q && q != afl->queue_cur) {
      return q;
    }
    attempts++;
  }

  return NULL;
}


struct queue_entry* binary_structure_duplicated_filter(afl_state_t* afl, u8* data, u32 len) {

  uint32_t sig[MINHASH_DIM];
  compute_minhash_signature(data, len, sig);

  for (int i = 0; i < BUCKET_CHUNKS; i++) {
    uint32_t* chunk = &sig[i * CHUNK_LEN];
    uint32_t bucket_id = murmur3_32((uint8_t*)chunk, CHUNK_LEN * 4, 0xABCD1234) % MINHASH_BUCKETS;

    struct bucket_node* node = FeaturePool[bucket_id];
    while (node) {
      struct queue_entry* cur = node->q;

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

      u8* other_data = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
      close(fd);
      if (other_data == MAP_FAILED) {
        node = node->next_in_bucket;
        continue;
      }

      BinData a = { .data = data, .len = len };
      BinData b = { .data = other_data, .len = st.st_size };

      float sim = hamming_similarity_weighted(a, b);

      munmap(other_data, st.st_size);

      if (sim > 0.8) {
        for (u32 i = 0; i < afl->queued_items; i++) {
          afl->queue_buf[i]->seen_flag = 0;
        }
        return NULL;  
      }

      node = node->next_in_bucket;
    }
  }

  for (u32 i = 0; i < afl->queued_items; i++) {
    afl->queue_buf[i]->seen_flag = 0;
  }
  struct queue_entry *match = find_similar_path_entry(afl);
  return match;
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
  
  