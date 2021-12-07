#include <apaz-libc.h>

int main(void) {
	String s = String_new_fromFile("samples/text.txt");
	bool eq = apaz_str_equals(s, "This is some text.\n");
	String_destroy(s);
	if (eq) puts("SUCCESS");
	return !eq;
}
