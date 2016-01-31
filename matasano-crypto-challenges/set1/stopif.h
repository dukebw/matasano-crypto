#ifndef STOPIF_H
#define STOPIF_H

#include <stdio.h>
#include <stdlib.h> // abort

// NOTE(brendan): source: 21st Century C by Ben Klemens

/** To where should I write errors? If this is \c NULL, write to \c stderr. */
static FILE *error_log = 0;

#define Stopif(assertion, ...)										\
        if (assertion)												\
		{															\
            fprintf(error_log ? error_log : stderr, __VA_ARGS__); 	\
            fprintf(error_log ? error_log : stderr, "\n");        	\
			abort();												\
        }

#endif /* STOPIF_H */
