#include <apaz-libc.h>

int main(void) {
	String s = String_new_fromFile((char*)"samples/text.txt");
	bool eq = apaz_str_equals(s, (char*)"This is some text.\n");
	String_destroy(s);
	if (eq) puts("SUCCESS");
	return !eq;
}
