#include <driver/ppm_ringbuffer.h>
#include <libscap/ringbuffer/devset.h>
#include <libscap/ringbuffer/ringbuffer_dump.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>

static inline bool all_zeros(const char* addr, size_t len) {
	for(int i = 0; i < len; i++) {
		if(addr[i] != 0) {
			return false;
		}
	}

	return true;
}

struct tick {
	size_t offset;
	char marker;
};

struct dump_span {
	size_t start;
	size_t end;
	const char* label;
	char marker;

	struct tick* ticks;
	size_t num_ticks;
};

static inline bool intervals_overlap(size_t start1, size_t end1, size_t start2, size_t end2) {
	// Handle the complement case for the first interval
	if(end1 < start1) {
		return (start1 < end2 || start2 < end1);
	}
	// Handle the complement case for the second interval
	if(end2 < start2) {
		return (start2 < end1 || start1 < end2);
	}
	// Normal case
	return (start1 < end2) && (start2 < end1);
}

static inline bool in_span(const struct dump_span* span, size_t offset) {
	if(span->start <= span->end) {
		// normal case
		return offset >= span->start && offset < span->end;
	} else {
		// inverted case, the actual span is [0, end) + [start, buffer_size]
		return offset < span->end || offset >= span->start;
	}
}

static inline bool next_in_span(const struct dump_span* span, size_t offset, size_t len) {
	if(offset + 1 < len) {
		return in_span(span, offset + 1);
	}
	return span->start > span->end;
}

static inline int next_tick(int current_tick, size_t offset, const struct dump_span* span) {
	for(int i = current_tick + 1; i < span->num_ticks; i++) {
		if(span->ticks[i].offset >= offset) {
			return i;
		}
	}

	return -1;
}

static int compare_ticks(const void* a, const void* b) {
	const struct tick* ta = a;
	const struct tick* tb = b;

	return ta->offset - tb->offset;
}

static inline void draw_span(size_t offset,
                             size_t len,
                             size_t bytes_per_line,
                             const struct dump_span* span,
                             void* tag,
                             size_t total_len) {
	if(!intervals_overlap(offset, offset + len, span->start, span->end)) {
		return;
	}

	fprintf(stderr, "RINGBUFFER DUMP[%p] %-8s  ", tag, span->label);

	int current_tick = -1;

	for(int i = 0; i < len; i++) {
		char c[4] = "   ";
		char s = ' ';
		if(in_span(span, offset + i)) {
			c[0] = span->marker;
			c[1] = span->marker;
			c[2] = '>';
			if(next_in_span(span, offset + i, total_len)) {
				c[2] = span->marker;
				s = span->marker;
			}
		} else if(next_in_span(span, offset + i, total_len)) {
			c[2] = '<';
		}

		if(current_tick != -1) {
			if(span->ticks[current_tick].offset == offset + i) {
				c[0] = span->ticks[current_tick].marker;
				current_tick = next_tick(current_tick, offset + i, span);
			}
		} else {
			current_tick = next_tick(current_tick, offset + i, span);
		}

		fprintf(stderr, "%s", c);

		if(i == bytes_per_line / 2 - 1) {
			fprintf(stderr, "%c", s);
		}
	}

	fprintf(stderr, "\n");
}

static inline void hexdump(const char* buffer,
                           size_t len,
                           void* tag,
                           const struct dump_span* spans,
                           size_t num_spans) {
	size_t i;
	size_t j;
	const size_t bytes_per_line = 32;
	bool blanks = false;

	for(i = 0; i < len; i += bytes_per_line) {
		if(all_zeros(buffer + i, MIN(len - i, bytes_per_line))) {
			blanks = true;
			continue;
		} else if(blanks) {
			fprintf(stderr, "RINGBUFFER DUMP[%p] ...\n", tag);
			blanks = false;
		}

		// Print offset
		fprintf(stderr, "RINGBUFFER DUMP[%p] %08zx  ", tag, i);

		// Print hex values
		for(j = 0; j < bytes_per_line; j++) {
			if(i + j < len) {
				fprintf(stderr, "%02x ", (unsigned char)buffer[i + j]);
			} else {
				fprintf(stderr, "   ");
			}

			if(j == bytes_per_line / 2 - 1) {
				fprintf(stderr, " ");
			}
		}

		// Print ASCII values
		fprintf(stderr, " | ");
		for(j = 0; j < bytes_per_line; j++) {
			if(i + j < len) {
				char c = buffer[i + j];
				if(c >= 32 && c <= 126)  // printable ASCII range
				{
					fprintf(stderr, "%c", c);
				} else {
					fprintf(stderr, ".");
				}
			}

			if(j == bytes_per_line / 2 - 1) {
				fprintf(stderr, " ");
			}
		}
		fprintf(stderr, "\n");

		for(int k = 0; k < num_spans; k++) {
			draw_span(i, MIN(len - i, bytes_per_line), bytes_per_line, &spans[k], tag, len);
		}
	}
}

static inline const char* push_event_ticks(const char* event,
                                           struct dump_span* span,
                                           size_t offset,
                                           size_t buffer_size) {
	if(!in_span(span, offset)) {
		fprintf(stderr, "tick %zu outside span (%zu, %zu)\n", offset, span->start, span->end);
		return NULL;
	}

	struct tick* new_ticks = realloc(span->ticks, (span->num_ticks + 5) * sizeof(struct tick));
	if(new_ticks == NULL) {
		fprintf(stderr, "Failed to allocate memory for ticks\n");
		return NULL;
	}

	new_ticks[span->num_ticks].offset = offset;  // tid
	new_ticks[span->num_ticks].marker = 't';

	new_ticks[span->num_ticks + 1].offset = (offset + 8) % buffer_size;  // ts
	new_ticks[span->num_ticks + 1].marker = 'T';

	new_ticks[span->num_ticks + 2].offset = (offset + 16) % buffer_size;  // len
	new_ticks[span->num_ticks + 2].marker = 'l';

	new_ticks[span->num_ticks + 3].offset = (offset + 20) % buffer_size;  // type
	new_ticks[span->num_ticks + 3].marker = '^';

	new_ticks[span->num_ticks + 4].offset = (offset + 22) % buffer_size;  // nparams
	new_ticks[span->num_ticks + 4].marker = 'n';

	span->ticks = new_ticks;
	span->num_ticks += 5;

	uint32_t nparams = ((scap_evt*)event)->nparams;
	size_t param_offset = offset + 26 + nparams * 2;
	new_ticks = realloc(span->ticks, (span->num_ticks + nparams) * sizeof(struct tick));
	if(new_ticks == NULL) {
		fprintf(stderr, "Failed to allocate memory for ticks\n");
		return NULL;
	}

	for(int i = 0; i < nparams; i++) {
		// none of the kernel-generated events use large param sizes
		uint16_t len = ((uint16_t*)(event + sizeof(scap_evt)))[i];

		new_ticks[span->num_ticks].offset = param_offset % buffer_size;  // param value
		new_ticks[span->num_ticks].marker = '0' + i;

		param_offset += len;

		span->ticks = new_ticks;
		span->num_ticks += 1;
	}

	return event + ((scap_evt*)event)->len;
}

void dump_ringbuffer(struct scap_device* dev) {
	char* buf_copy = malloc(dev->m_buffer_size);
	if(buf_copy == NULL) {
		fprintf(stderr, "RINGBUFFER_DUMP[%p] Failed to allocate buffer for ringbuffer dump\n", dev);
	} else {
		// do this soon so that the producer doesn't overwrite *too* much
		memcpy(buf_copy, dev->m_buffer, dev->m_buffer_size);
	}
	fprintf(stderr, "RINGBUFFER DUMP[%p] Ringbuffer metadata:\n", dev);
	fprintf(stderr, "RINGBUFFER DUMP[%p] m_buffer_size: 0x%lx\n", dev, dev->m_buffer_size);
	fprintf(stderr, "RINGBUFFER DUMP[%p] m_lastreadsize: 0x%x\n", dev, dev->m_lastreadsize);
	fprintf(stderr,
	        "RINGBUFFER DUMP[%p] m_sn_next_event: 0x%lx\n",
	        dev,
	        dev->m_sn_next_event - dev->m_buffer);
	fprintf(stderr, "RINGBUFFER DUMP[%p] m_sn_len: 0x%x\n", dev, dev->m_sn_len);
	fprintf(stderr, "RINGBUFFER DUMP[%p] head: 0x%x\n", dev, dev->m_bufinfo->head);
	fprintf(stderr, "RINGBUFFER DUMP[%p] tail: 0x%x\n", dev, dev->m_bufinfo->tail);
	fprintf(stderr, "RINGBUFFER DUMP[%p] ---\n", dev);
	fprintf(stderr,
	        "RINGBUFFER DUMP[%p] last read: 0x%x .. 0x%x\n",
	        dev,
	        dev->m_bufinfo->tail,
	        dev->m_bufinfo->tail + dev->m_lastreadsize);

	struct dump_span spans[] = {
	        {.start = dev->m_bufinfo->tail,
	         .end = (dev->m_bufinfo->tail + dev->m_lastreadsize) % dev->m_buffer_size,
	         .label = "lastread",
	         .marker = '~'},
	        {.start = dev->m_sn_next_event - dev->m_buffer,
	         .end = (dev->m_sn_next_event - dev->m_buffer + dev->m_sn_len) % dev->m_buffer_size,
	         .label = "next evt",
	         .marker = '*'},
	        {.start = dev->m_bufinfo->tail,
	         .end = dev->m_bufinfo->head,
	         .label = "used",
	         .marker = '-'},
	};

	const char* event = dev->m_buffer + dev->m_bufinfo->tail;
	while(event && event < dev->m_buffer + dev->m_bufinfo->tail + dev->m_lastreadsize) {
		push_event_ticks(event, &spans[0], event - dev->m_buffer, dev->m_buffer_size);
		event += ((scap_evt*)event)->len;
	}
	qsort(spans[0].ticks, spans[0].num_ticks, sizeof(struct tick), compare_ticks);

	event = dev->m_sn_next_event;
	while(event && event < dev->m_sn_next_event + dev->m_sn_len) {
		push_event_ticks(event, &spans[1], event - dev->m_buffer, dev->m_buffer_size);
		event += ((scap_evt*)event)->len;
	}
	qsort(spans[1].ticks, spans[1].num_ticks, sizeof(struct tick), compare_ticks);

	if(buf_copy != NULL) {
		fprintf(stderr,
		        "RINGBUFFER DUMP[%p] Buffer content: "
		        "----------------------------------------------------------------------------------"
		        "---------\n",
		        dev);
		hexdump(buf_copy, dev->m_buffer_size, dev, spans, sizeof(spans) / sizeof(spans[0]));
		fprintf(stderr,
		        "RINGBUFFER DUMP[%p] End of buffer content "
		        "----------------------------------------------------------------------------------"
		        "---\n",
		        dev);
		free(buf_copy);
	}

	free(spans[0].ticks);
	free(spans[1].ticks);
}
