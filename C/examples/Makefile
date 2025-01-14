
SRC_DIR = ../src/
SRC_DIR_EXTERNAL = ../external

PROJECT_BASE_DIR = .

SRCS_COMMON = \
	$(SRC_DIR_EXTERNAL)/lz4/lib/lz4.c \
	$(SRC_DIR_EXTERNAL)/lz4/lib/lz4hc.c \
	$(SRC_DIR_EXTERNAL)/Monocypher/src/monocypher.c \
	$(SRC_DIR)/ssbf_common.c \
	$(SRC_DIR)/ssbf_encoder.c \

SRCS_ENCODE= $(SRCS_COMMON) \
	$(SRC_DIR)/../examples/ssbf_encode_file.c \


SRCS_EXPLAIN= $(SRCS_COMMON) \
	$(SRC_DIR)/../examples/ssbf_explain_file.c \
	$(SRC_DIR)/ssbf_decoder.c \
	$(SRC_DIR)/ssbf_explain.c \


LZ4_DEFINES+=-D LZ4HC_HEAPMODE=0 #-D LZ4_HC_STATIC_LINKING_ONLY

DEFINES= \
	$(LZ4_DEFINES) \
	-D _GNU_SOURCE \

CFLAGS+=-g -ggdb3 \
	-Wall -Wextra -Werror -Wshadow \
	-Wundef \
	-Wno-sign-conversion \
	-std=c11 -pedantic \
	-fstack-protector-all
	-fsanitize=address,undefined \

CC=gcc

INCLUDE_DIRS = . \
	$(SRC_DIR) \
	$(SRC_DIR_EXTERNAL)/lz4/lib/ \
	$(SRC_DIR_EXTERNAL)/Monocypher/src/ \


INCS_RELATIVE_PATH:= $(patsubst %, -I%, $(INCLUDE_DIRS))

SRCS_ENCODE_FULL_PATH:=$(shell readlink -f $(SRCS_ENCODE))
SRCS_EXPLAIN_FULL_PATH:=$(shell readlink -f $(SRCS_EXPLAIN))

all: ssbf_encode_file ssbf_explain_file

ssbf_encode_file: $(SRCS_ENCODE_FULL_PATH) 
	@$(CC) \
	$(CFLAGS) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_ENCODE_FULL_PATH)  -o $@

ssbf_explain_file: $(SRCS_EXPLAIN_FULL_PATH)
	@$(CC) \
	$(CFLAGS) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_EXPLAIN_FULL_PATH)  -o $@

clean:
	@rm ssbf_encode_file

rtags_encode:
	@echo "Updating rtags..."
	@rc --project-root . -c gcc \
	$(CFLAGS) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_ENCODE_FULL_PATH) \

rtags_explain:
	@echo "Updating rtags..."
	@rc --project-root . -c gcc \
	$(CFLAGS) \
	$(DEFINES) \
	$(LIBS) \
	$(INCS_RELATIVE_PATH) \
	$(SRCS_EXPLAIN_FULL_PATH) \
