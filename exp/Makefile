TARGET := bt_power

.PHONY:
all: $(TARGET)

$(TARGET): $(TARGET).c bluetooth.h
	@echo CC $@
	@gcc -Wall -Wextra -Werror -O2 -o $@ $<

.PHONY:
clean:
	@echo RM $(TARGET)
	@rm -f $(TARGET)
