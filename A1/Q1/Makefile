TARGET_CODE := main.c
EXE := main

TARGET_LIB_NAME = clefia_t_table
TARGET_LIB_PATH = lib

COMPILE_OPTS := -o $(EXE) -I$(TARGET_LIB_PATH)
COMPILE_CMD := gcc $(COMPILE_OPTS)

OTHER_PATH := others
TABLE_OUTPUT := T_tables.txt

default: $(TARGET_CODE) $(TARGET_LIB_PATH)/$(TARGET_LIB_NAME).h $(TARGET_LIB_PATH)/$(TARGET_LIB_NAME).c
	@echo "Compiling and executing files..."
	@$(COMPILE_CMD) $(TARGET_CODE)
	@./$(EXE)

generate_tables:
	@echo "Generating text file" $(TABLE_OUTPUT) "containing the T tables..."
	@gcc -o tables $(OTHER_PATH)/get_t_tables.c
	@./tables > $(TABLE_OUTPUT)
	@rm tables
	
clean:
	@echo "Cleaning generated exe files..."
	@rm $(EXE)
