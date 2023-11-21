#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detection_engine.h"
#include "utils.h"
#include <yara.h>

static int yara_engine_process(char *, size_t, Threat *);
static int yara_engine_init(void);
static void yara_engine_reset(void);
static void yara_engine_destroy(void);

static YR_RULES* rules;

static struct ScanParameters {
	char *id;
	int gotcha; // 0 if nothing was found, 1 if something was found
} scan_params;

DetectionEngine yara_engine = {
   .name = "yara",
   .descr = "yara Detection Engine",
   .init = &yara_engine_init,
   .destroy = &yara_engine_destroy,
   .reset = &yara_engine_reset,
   .process = &yara_engine_process
};

int scan_callback_function(
   YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data){

   struct ScanParameters *sp = (struct ScanParameters *) user_data;
   YR_RULE *yr = (YR_RULE *) message_data;

   if (message == CALLBACK_MSG_RULE_MATCHING) {
      sp->id = strdup(yr->identifier);
      sp->gotcha = 1;
      // we've got one matching candidate, no need to search for more
      return CALLBACK_ABORT; 
   }

   return CALLBACK_CONTINUE;
}

/*
 * Function: yara_engine_process()
 *
 * Purpose: Process a new data group with the yara engine. 
 *
 * Arguments:
 *           data => A character array with the data to process
 *           len  => The character array length
 *           threat => The threat data structure to be filled in if a
 *                threat has been detected (see return value 1)
 *
 * Returns:   0 => No threat detected
 *            1 => Threat detected
 *           -1 => An error occured
 */
int yara_engine_process(char *data, size_t len, Threat *threat)
{
   const char *p;
   int block_size, block_num = 0;
   char threat_msg[500];
   void *block;

   if((data == NULL) || (len == 0))
      return 0;
   
   while((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
              block_num++))) 
   {
      block = malloc(block_size);
      if (block == NULL) {
         perror("malloc failed while building block\n");
	 return -1;
      }

      memcpy(block, p, block_size);
      scan_params.gotcha = 0;

      int error_scan_mem;
      error_scan_mem = yr_rules_scan_mem(rules, (const uint8_t *) p, block_size, SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING, scan_callback_function, &scan_params, 0);

      if ((error_scan_mem  == ERROR_SUCCESS) && scan_params.gotcha){
         threat->payload = block;
         threat->length = block_size;
         threat->severity = SEVERITY_HIGH;
         snprintf(threat_msg, 500, 
            "yara detected suspicious payload at block %i (%s)",
            block_num, scan_params.id);
	 threat_msg[499] = '\0';
         threat->msg = strdup(threat_msg);
	 free(scan_params.id);
         scan_params.id = NULL;
         return 1;
      } else if (error_scan_mem  != ERROR_SUCCESS){ // yara scanning errors
	 free(block);
	 fprintf(stderr, "yara scanning error\n");
	 return -1;
      }

      // all is good, didn't find anything
      free(block);
   }

   return 0;
}

/*
 * Function: yara_engine_init()
 *
 * Purpose: Initialize important structures for the yara engine.
 *
 * Arguments:
 *
 * Returns:   0 => Error occured
 *            1 => Everything ok
 */
int yara_engine_init(void) 
{
   YR_COMPILER* compiler = NULL;
   int error_compiler;

   rules = NULL;

   if(yr_initialize() !=ERROR_SUCCESS){ 
   	fprintf(stderr, "error in initializing yara library\n");
	return 0;
   }

   error_compiler = yr_compiler_create(&compiler);
   if (error_compiler != ERROR_SUCCESS){
	fprintf(stderr, "failed to create yara compiler\n");
	goto err_compiler;
   }

   FILE *yr_file;
   if ((yr_file = fopen("./yara/yara_rules.yar", "r")) == NULL) {
	   if ((yr_file = fopen(YARA_RULES_INDEX,"r")) == NULL) {
		fprintf(stderr, "failed to open yara rules file\n");
   		goto err_open;
	   }
   }

   int error_add_file;
   error_add_file = yr_compiler_add_file(compiler, yr_file, NULL, NULL);
   if (error_add_file)
   {
      fprintf(stderr, "%i errors found during yara rules compilation\n", 
		      error_add_file);
      goto err_compiler_add_file;
   }
   
   int error_get_rules;
   error_get_rules = yr_compiler_get_rules(compiler, &rules);
   if (error_get_rules != ERROR_SUCCESS){
   	fprintf(stderr, "error while getting the compiled rules from the compiler\n");
	goto err_compiler_get_rules;
   }

   fclose(yr_file);
   yr_compiler_destroy(compiler);
   return 1;

err_compiler_get_rules:
   rules = NULL;
err_compiler_add_file:
   fclose(yr_file);
err_open:
   yr_compiler_destroy(compiler);
err_compiler:
   yr_finalize();
   return 0;
}

/*
 * Function: yara_engine_reset()
 *
 * Purpose: Not used by yara engine
 *
 * Arguments:
 *
 * Returns:
 */
void yara_engine_reset(void)
{
   return;
}

/*
 * Function: yara_engine_destroy()
 *
 * Purpose: Shut down the yara engine
 *
 * Arguments:
 *
 * Returns:
 */
void yara_engine_destroy(void)
{
	if (scan_params.id) {
		free(scan_params.id);
	}

	if (rules) {
		yr_rules_destroy(rules);
	}

	if (yr_finalize() != ERROR_SUCCESS) {
		fprintf(stderr, "error while destroying yara engine\n");
	}
}
