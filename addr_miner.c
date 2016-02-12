/**
 The MIT License (MIT)

 Copyright (c) 2014 <bvsh>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include <pthread.h>
#include <time.h>
#include <signal.h>

#define CALL_SUCCESS 1
#define FOREVER 1

// For bitcoin version byte is 0
#define VERSION_BYTE 0
#define OUTPUT_FILE "addresses.txt"


char *out_file = OUTPUT_FILE;
uint8_t ver_byte = VERSION_BYTE;
char *target_str = NULL;
int target_str_len = 0;
int ignore_case = 0;

#define B58_BASE 58
static const char _b58_alphabet[] =
   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";



#define MAX_SCRATCH 256
void base58_encode(uint8_t *data, int data_len, uint8_t *ret)
{
   BN_ULONG mod;
   BIGNUM *n = BN_new();
   char scratch_buf[MAX_SCRATCH];
   int i;
   uint8_t *ptr;
   
   BN_bin2bn(data, data_len, n);

   for(i = 0; BN_get_word(n) > 0 && i < MAX_SCRATCH; i++)
   {
      mod = BN_div_word(n, B58_BASE);
      scratch_buf[i] = _b58_alphabet[mod];
   }
   
   for(ptr = ret; i > 0;)
   {
      *ptr++ = scratch_buf[--i];
   }

   *ptr = 0;
   BN_free(n);
   
}

char *base58_encode_256bits(uint8_t *data)
{
   static char encoded[100];
   int i, p;
   BN_ULONG mod;

   uint8_t *ptr;
   
   BIGNUM *n = BN_new();
   BN_bin2bn(data, 25, n);

   /* sizeof is 59, not 58 */
   p = sizeof(encoded) - 1;
   memset(encoded, 0, sizeof(encoded));
   
   
   for(encoded[p--]=0; BN_get_word(n) >= 58; ) 
   {
      mod = BN_div_word(n, 58);
      encoded[p--]=_b58_alphabet[mod];
      
      if(p==0) 
      {
	 BN_free(n);
	 return NULL;
	 /* string buffer overflow */
      }
   }
   if((mod = BN_get_word(n)) > 0) 
   {
      encoded[p]=_b58_alphabet[mod];
   }

   for(ptr = data; !*ptr; ptr++)
   {
      encoded[--p] = *_b58_alphabet;
   }
   
   BN_free(n);
   return &encoded[p];
}

void handleErrors()
{
   printf("Whining happens here\n");
   exit(-1);
}

void bin2string (uint8_t *bin, char *str, size_t len)
{
   uint8_t *ptr = bin;
   int i = 0;
   
   while(len)
   {
      sprintf(str + (i*2), "%02x", *ptr);
      len--;
      ptr++;
      i++;
   }
   str[i*2] = '\0';
}

void show_version_byte_list(void)
{
   printf("Tiny list of version bytes for some currencies:\n");
   printf("Bitcoin: 0\n");
   printf("Namecoin: ?\n");
   printf("Primecoin: 23\n");
}

void show_usage(char *exec_name)
{
   printf("This program will generate priv/pub keys pairs looking for an address that would start with a target string.\n");
   printf("Something that can get you 1Love* Bitcoin address.\n\n");
   
   printf("Usage: %s <params>\n", exec_name);
   printf("Where params could be: \n");
   printf("-o [filename]\t\t\t Specifies filename to store results (default: %s)\n", OUTPUT_FILE);
   printf("-b [decimal version byte]\t Version byte of the currency you are looking an address for (default: 0 for Bitcoin)\n");
   printf("-t [target string]\t\t String you want to find, ex. to look for 1Love* address enter \"Love\"\n");
   printf("-i \t\t\t\t Will ignore case when comparing to target, this can save you some time searching\n");
   printf("-n [workers]\t\t TODO: Number of worker threads you want to run (default: 1)\n\n");
   
   
   printf("-s \t\t\t\t Will show version bytes for some currencies\n");
   printf("-h\t\t\t\t Will display this usage info\n");  
}

void submit_address(const BIGNUM *priv_key, char *bin_address, uint8_t ver_byte)
{
   uint8_t sha_digest[SHA256_DIGEST_LENGTH];
   char buf[65];   
   SHA256_CTX sha256;
   uint8_t *priv;
   int priv_bytes_len;

   // compute the checksum
   SHA256_Init(&sha256);
   SHA256_Update(&sha256, bin_address, 21);
   SHA256_Final(sha_digest, &sha256);
   SHA256_Init(&sha256);
   SHA256_Update(&sha256, sha_digest, SHA256_DIGEST_LENGTH);
   SHA256_Final(sha_digest, &sha256);

   // append checksum
   memcpy(bin_address + 21, sha_digest, 4);

   // handle the private key
   priv_bytes_len = BN_num_bytes(priv_key) + 5;
   
   priv = (uint8_t *)malloc(priv_bytes_len);
   if(priv)
   {
      *priv = 128 + 23; // mainnet privkey

      BN_bn2bin(priv_key, priv + 1);

      SHA256_Init(&sha256);
      SHA256_Update(&sha256, priv, priv_bytes_len - 4);
      SHA256_Final(sha_digest, &sha256);
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, sha_digest, SHA256_DIGEST_LENGTH);
      SHA256_Final(sha_digest, &sha256);

      // append checksum to the binary priv key
      memcpy(priv + priv_bytes_len - 4, sha_digest, 4);

      printf("Pub: %s\n", base58_encode_256bits(bin_address));
      bin2string(sha_digest, buf, SHA256_DIGEST_LENGTH);
      printf("SHA: %s\n", buf);
      
      bin2string(priv, buf, priv_bytes_len);
      printf("XPRIV: %s\n", buf);      
      
      base58_encode(priv, priv_bytes_len, buf);
      printf("WIP: %s\n", buf);
      
      printf("Priv: %s\n", BN_bn2hex(priv_key));
      printf("--------------------------------\n");
   
      free(priv);
   }
   else
   {
      printf("Error allocating %d bytes\n", priv_bytes_len);
   }
}

typedef struct
{
   pthread_t thread_id;
   int active;
   int alive;
   uint32_t tries;
   uint32_t found_targets;
} WorkerCtx;
   

void worker_thread(WorkerCtx *thread_ctx)
{
   
   EC_KEY *eckey = NULL;
   EC_POINT *pub_key = NULL;
   BIGNUM *priv_key = NULL;  
   
   const EC_GROUP *group = NULL;
   
   uint8_t _coords[65];
   uint8_t *crd;
   
   BIGNUM x, y;
   
   uint8_t sha_digest[SHA256_DIGEST_LENGTH];
   char sha_digest_str[65];   
   SHA256_CTX sha256;

   uint8_t _uint256[32];
   
   uint8_t *bin_address = _uint256;
   
   RIPEMD160_CTX ripemd160;

   BN_CTX *bn_ctx = NULL;

   char ch_address[33];
   
   printf("Worker thread created\n");
   thread_ctx->alive = 1;

   bn_ctx = BN_CTX_new();

   BN_init(&x);
   BN_init(&y);
   

   while(thread_ctx->active)
   {
      thread_ctx->tries++;
      memset(sha_digest, 0, SHA256_DIGEST_LENGTH);
      
      eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
      if(eckey)
      {	 
	 if(CALL_SUCCESS != EC_KEY_generate_key(eckey))
	    handleErrors();

	 group = EC_KEY_get0_group(eckey);
	 pub_key = EC_KEY_get0_public_key(eckey);
	 priv_key = EC_KEY_get0_private_key(eckey);

	 memset(_coords, 0, 65);
	 _coords[0] = 0x04;
	 crd = _coords + 1;
      
	 EC_POINT_get_affine_coordinates_GFp(group, pub_key, &x, &y, bn_ctx);
      
	 crd += BN_bn2bin(&x, crd);
	 BN_bn2bin(&y, crd);

	 SHA256_Init(&sha256);
	 SHA256_Update(&sha256, _coords, 65);
	 SHA256_Final(sha_digest, &sha256);

	 RIPEMD160_Init(&ripemd160);
	 RIPEMD160_Update(&ripemd160, sha_digest, SHA256_DIGEST_LENGTH);

	 memset(&_uint256, 0, 32);
	 *bin_address = ver_byte;
	 RIPEMD160_Final(&bin_address[1], &ripemd160);
	 // we skip tail computation for now to save time
      
	 //char *ch_address = base58_encode_256bits(bin_address);

	 base58_encode(bin_address, 25, ch_address);
	 
	 if(ignore_case)
	 {
	    if(!strncasecmp(ch_address + 1, target_str, target_str_len))
	    {
	       thread_ctx->found_targets++;
	       submit_address(priv_key, bin_address, ver_byte);
	    }
	 }
	 else if(!strncmp(ch_address + 1, target_str, target_str_len))
	 {
	    thread_ctx->found_targets++;	    
	    submit_address(priv_key, bin_address, ver_byte);
	 }

	 EC_KEY_free(eckey);
	 eckey = NULL;
      }
      
   }
   
   BN_CTX_free(bn_ctx);
}


volatile int exit_asap = 0;
static void signal_handler(int signum)
{
   exit_asap = 1;
}

int main(int argc, char *argv[])
{
   int param;
   int n_of_threads = 1;
   WorkerCtx *workers;
   time_t start, end;
   double duration;
   struct sigaction sa;
   
   int i;

   while((param = getopt(argc, argv, "sihb:t:o:n:")) != -1)
   {
      switch(param)
      {
	 case('b'):
	    // version byte
	    ver_byte = atoi(optarg);
	    printf("Using version byte: %d\n", ver_byte);
	    
	    break;
	 case('t'):
	    // target string
	    target_str = optarg;
	    target_str_len = strlen(target_str);
	    printf("Looking for target: \"%s\"\n", target_str);
	    
	    break;
	 case('o'):
	    // output file
	    out_file = optarg;
	    printf("Using %s to store results\n", out_file);
	    
	    break;
	 case('i'):
	    ignore_case = 1;
	    printf("Looking for target ignoring case\n");
	    break;
	 case('n'):
	    n_of_threads = atoi(optarg);
	    printf("Starting %d working threads\n", n_of_threads);
	    break;
	    
	 case('s'):
	    show_version_byte_list();
	    exit(EXIT_SUCCESS);
	    break;
	    
	 case('h'):
	    show_usage(*argv);
	    exit(EXIT_SUCCESS);
	    break;
      }
   }

   if(!target_str)
   {
      show_usage(*argv);
      printf("\n\nNo target string specified, exiting.\n");
      exit(EXIT_FAILURE);
   }

   if(n_of_threads < 1)
   {
      printf("\n\nInvalid number of threads specified, exiting.\n");
      exit(EXIT_FAILURE);
   }
   
   // create worker contexts
   workers = (WorkerCtx *) calloc(n_of_threads, sizeof(WorkerCtx));
   
   // spawn threads
   if(workers)
   {
      for(i = 0; i < n_of_threads; i++)
      {
	 workers[i].active = 1;
	 pthread_create(&workers[i].thread_id, NULL, worker_thread, &workers[i]);
      }

      // install sigactions
      sa.sa_handler = signal_handler;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = SA_RESTART;
      sigaction(SIGINT, &sa, NULL);
      

      while(FOREVER)
      {
	 if(exit_asap)
	 {
	    printf("Cleaning up now\n");
	    for(i = 0; i < n_of_threads; i++)
	    {
	       if(workers[i].alive)
	       {
		  workers[i].active = 0;
		  pthread_join(workers[i].thread_id, NULL);
		  printf("Worker %d terminated\n", i);
	       }
	       
	    }
	    // get out of forever loop
	    break;
	 }
	 
	 start = clock();
	 sleep(60);
	 end = clock();

	 duration = ((double) (end - start)/CLOCKS_PER_SEC);
	 
	 printf("Tries/s: ");
	 for(i = 0; i < n_of_threads; i++)
	 {
	    printf("%.2f ", (float) workers[i].tries / duration);
	    
	 }
	 printf(" | targets: ");
	 for(i = 0; i < n_of_threads; i++)
	 {
	    printf("%d ", workers[i].found_targets);
	    // nill stats
	    workers[i].tries = 0;	    
	 }
	 printf("\n");
      }

      
      free(workers);
   }

   
   return 0;
}





