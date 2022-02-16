int main(void) {
    void* lblval = &&lbl;
    goto* lblval;

lbl:;
    return 0;
}
