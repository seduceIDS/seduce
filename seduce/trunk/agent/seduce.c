#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "detect_engine.h"

/* exported by the appropriate engine */
extern DetectEngine engine;

void *load_file(const char *filename, size_t *fsize)
{
	FILE *f;
	void *buff;
	struct stat st;

	if (stat(filename, &st) == -1) {
		fprintf(stderr, "could not stat file %s: %s\n",
			filename, strerror(errno));
		return NULL;
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "file %s is not a regular file!",
			filename);
		return NULL;
	}

	*fsize = st.st_size;

	if ((f = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "file %s could not be openned: %s\n",
			filename, strerror(errno));
		return NULL;
	}
	
	if ((buff = calloc(1, *fsize)) == NULL) {
		fprintf(stderr,"could not allocate buffer for file %s: %s\n",
			filename, strerror(errno));
		fclose(f);
		return NULL;
	}

	if (fread(buff, *fsize, 1, f) != 1) {
		fprintf(stderr, "error: short read from file %s\n",
				filename);
		fclose(f);
		return NULL;
	}
	
	fclose(f);

	return buff;
}

int main(int argc, char **argv)
{
	void *buff;
	size_t fsize;
	Threat t;
	int ret;
	struct timeval start, finish, result;

	if (--argc != 1) {
		fprintf(stderr,"usage %s <payload-file>\n", argv[0]);
		exit(1);
	}

	if ((buff = load_file(argv[1], &fsize)) == NULL) 
		exit(1);

	if (engine.init() == 0){
		fprintf(stderr, "could not init detection engine '%s'\n",
			engine.name);
		exit(1);
	}

	engine.reset();

	gettimeofday(&start, NULL);
	ret = engine.process(buff, fsize, &t);
	gettimeofday(&finish, NULL);

	switch(ret) {
	case -1:
		fprintf(stderr, "Detection engine exited prematurely\n");
		free(buff);
		engine.destroy();
		exit(1);
	case 0:
		printf("No threat was detected\n");
		break;
	case 1:
		printf("Threat detected - %s\n", t.msg);
		destroy_threat(&t);
		break;
	}

	timersub(&finish, &start, &result);

	printf("Detection engine time: %ld sec %ld usec\n",
		result.tv_sec, result.tv_usec);

	engine.destroy();
	free(buff);
	 
	return 0;
}

