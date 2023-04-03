int main(void) {
    void* lblval = &&lbl;
    goto* lblval;
    return 1;
lbl:;
    return 0;
}
