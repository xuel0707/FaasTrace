TARGET = ${notdir $(CURDIR)}

SRC_DIR = .
SRC_SUBDIR += threads ebpf
INCLUDE_DIR += . json/include 
OBJ_DIR = obj

CC = g++
C_FLAGS = -g -Wall -Iebpf$(LIBBPF_DIST_DIR)/usr/include -I/usr/include/cpprest -I/usr/include/cjson
LD = $(CC)
INCLUDES := $(addprefix -I,$(INCLUDE_DIR))
LD_FLAGS += -Lebpf/$(LIBBPF_DIST_LIB_DIR)
LD_LIBS = -lbpf -lcurl -lcpprest -lboost_system -lboost_thread -lssl -lcrypto -lcjson

TYPE = cpp

SRCS = $(wildcard *.$(TYPE)) $(foreach subdir, $(SRC_SUBDIR), $(wildcard $(subdir)/*.$(TYPE)))
OBJS = $(patsubst %.$(TYPE), $(OBJ_DIR)/%.o, $(SRCS)) $(OBJ_DIR)/load_ebpf.o

vpath %.$(TYPE) $(sort $(dir $(SRCS))) 

EBPF_EXECVE_HOOK_PROGRAM	= ebpf_process_kern.o
EBPF_FILE_HOOK_PROGRAM		= ebpf_file_kern.o
EBPF_NET_HOOK_PROGRAM		= ebpf_net_kern.o

all : make_ebpf $(TARGET)
	@echo "Built target:" $^
	@echo "Done"

$(TARGET) : $(OBJS)
	@mkdir -p $(@D)
	@echo "Linking" $@ "from" $^ "..."
	$(LD) -o $@ $^ $(LD_FLAGS) $(LD_LIBS)
	@echo "Link finished\n"

$(OBJ_DIR)/%.o : %.$(TYPE)
	@mkdir -p $(@D)
	@echo "Compiling" $@ "from" $< "..."
	$(CC) $(C_FLAGS) $(INCLUDES) -c $< -o $@
	@echo "Compile finished\n"

make_ebpf:
	make -C ebpf
	mv ebpf/load_ebpf.o ${OBJ_DIR}
	mv ebpf/${EBPF_EXECVE_HOOK_PROGRAM} $(CURDIR)
	mv ebpf/${EBPF_FILE_HOOK_PROGRAM} $(CURDIR)
	mv ebpf/${EBPF_NET_HOOK_PROGRAM} $(CURDIR)
	@echo "ebpf program is generated"	

ebpf-clean:
	make -C ebpf clean
	@echo "TODO: impl. ebpf-clean"

.PHONY : clean cleanobj
clean : cleanobj
	@echo "Remove all executable files"
	rm -f $(TARGET)
	rm -f *.o
	rm -f ebpf/*.o
	rm -f ebpf/*.ll
cleanobj :
	@echo "Remove object files"
	rm -rf $(OBJ_DIR)/*.o
