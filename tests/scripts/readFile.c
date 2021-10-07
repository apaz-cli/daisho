#include <assert.h>
#include <apaz-libc.h>

int main() {
	String s = String_new_fromFile("samples/text.txt");
	bool eq = apaz_str_equals(s, "This is some text.\n");
	String_destroy(s);
	return !eq;
}
